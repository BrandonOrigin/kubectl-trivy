package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// TrivyReport mirrors the subset of `trivy image --format json` output we consume.
type TrivyReport struct {
	Results []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity         string `json:"Severity"`
}

type vulResult struct {
	image     string
	pods      string
	critical  int
	high      int
	med       int
	low       int
	unknown   int
	supported bool
}

// severities are the Trivy severity levels reported, in descending order of importance.
var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

func getImages(ctx context.Context, namespace string) (map[string]string, error) {
	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig %q: %w", kubeconfig, err)
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	// Get pods in the namespace
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if apierrors.IsNotFound(err) {
		fmt.Printf("namespace %s not found\n", namespace)
		return map[string]string{}, nil
	} else if err != nil {
		return nil, fmt.Errorf("listing pods in namespace %s: %w", namespace, err)
	}

	fmt.Printf("Found %d pods in namespace %s\n", len(pods.Items), namespace)
	return imagesFromPods(pods.Items), nil
}

// imagesFromPods maps each unique container image to the comma-separated list of
// pods running it.
//
// All three container lists on the pod spec are inspected. Init containers matter
// because they run with the same volumes and service account as the main
// containers, and ephemeral containers because `kubectl debug` injects images that
// never went through review. Sidecar-style init containers (`restartPolicy: Always`)
// need no special handling: they appear in InitContainers like any other, and their
// image is worth scanning for the same reason.
func imagesFromPods(pods []corev1.Pod) map[string]string {
	// Pod names are collected as a set, so a pod running one image across several
	// of its containers is still listed once.
	podsByImage := map[string]map[string]struct{}{}
	record := func(image, podName string) {
		if image == "" {
			return
		}
		if podsByImage[image] == nil {
			podsByImage[image] = map[string]struct{}{}
		}
		podsByImage[image][podName] = struct{}{}
	}

	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			record(container.Image, pod.Name)
		}
		for _, container := range pod.Spec.InitContainers {
			record(container.Image, pod.Name)
		}
		// EphemeralContainer reaches Image through an embedded
		// EphemeralContainerCommon, so it cannot share a loop with the others.
		for _, container := range pod.Spec.EphemeralContainers {
			record(container.Image, pod.Name)
		}
	}

	images := make(map[string]string, len(podsByImage))
	for image, podSet := range podsByImage {
		names := make([]string, 0, len(podSet))
		for name := range podSet {
			names = append(names, name)
		}
		// Sorted so the Pods column is stable across runs; Go randomizes map
		// iteration order.
		sort.Strings(names)
		images[image] = strings.Join(names, ",")
	}
	return images
}

// trivyServerURL normalizes the --server value into a URL Trivy accepts, so that
// both a bare `host:port` and a fully qualified `http(s)://host:port` work.
func trivyServerURL(server string) string {
	server = strings.TrimSpace(server)
	server = strings.TrimSuffix(server, "/")
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		return server
	}
	return "http://" + server
}

// scanImage runs a client/server Trivy scan for one image and returns the
// vulnerability count per severity level.
func scanImage(ctx context.Context, serverURL, image string) (map[string]int, error) {
	cmd := exec.CommandContext(ctx, "trivy", "image", "--server", serverURL, "--format", "json", image)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("running trivy: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("running trivy: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("parsing trivy JSON output: %w", err)
	}
	return countSeverities(report), nil
}

// countSeverities tallies vulnerabilities per severity level across all results.
func countSeverities(report TrivyReport) map[string]int {
	counts := map[string]int{}
	for _, severity := range severities {
		counts[severity] = 0
	}
	for _, result := range report.Results {
		for _, vul := range result.Vulnerabilities {
			severity := strings.ToUpper(strings.TrimSpace(vul.Severity))
			if _, known := counts[severity]; !known {
				severity = "UNKNOWN"
			}
			counts[severity]++
		}
	}
	return counts
}

// sortVulResults orders images by descending severity, most severe first. Images
// that could not be scanned carry -1 counts and therefore sort last.
func sortVulResults(results []vulResult) {
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.critical != b.critical {
			return a.critical > b.critical
		}
		if a.high != b.high {
			return a.high > b.high
		}
		if a.med != b.med {
			return a.med > b.med
		}
		if a.low != b.low {
			return a.low > b.low
		}
		if a.unknown != b.unknown {
			return a.unknown > b.unknown
		}
		return a.image < b.image
	})
}

func showScanResult(ctx context.Context, images map[string]string) error {
	serverURL := trivyServerURL(trivyServer)

	imgVulResults := make([]vulResult, 0, len(images))
	for img, pods := range images {
		counts, err := scanImage(ctx, serverURL, img)
		if err != nil {
			// A cancelled context means the user interrupted us, not a bad image.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			fmt.Fprintf(os.Stderr, "Failed to scan %s: %v\n", img, err)
			imgVulResults = append(imgVulResults, vulResult{
				image: img, pods: pods,
				critical: -1, high: -1, med: -1, low: -1, unknown: -1,
				supported: false,
			})
			continue
		}

		imgVulResults = append(imgVulResults, vulResult{
			image: img, pods: pods,
			critical:  counts["CRITICAL"],
			high:      counts["HIGH"],
			med:       counts["MEDIUM"],
			low:       counts["LOW"],
			unknown:   counts["UNKNOWN"],
			supported: true,
		})
	}

	sortVulResults(imgVulResults)

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Image", "Pods", "Critical", "High", "Medium", "Low", "Unknown"})
	for _, r := range imgVulResults {
		unknown := fmt.Sprintf("%d", r.unknown)
		if !r.supported {
			unknown += " (Unsupported)"
		}
		t.AppendRow(table.Row{r.image, r.pods, r.critical, r.high, r.med, r.low, unknown})
	}
	t.Render()

	return nil
}
