package cmd

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTrivyServerURL(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   string
	}{
		{"bare host:port", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"hostname only", "trivy.internal", "http://trivy.internal"},
		{"http prefix preserved", "http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"https prefix preserved", "https://trivy.example.com", "https://trivy.example.com"},
		{"trailing slash trimmed", "http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
		{"surrounding whitespace trimmed", "  127.0.0.1:8080  ", "http://127.0.0.1:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trivyServerURL(tt.server); got != tt.want {
				t.Errorf("trivyServerURL(%q) = %q, want %q", tt.server, got, tt.want)
			}
		})
	}
}

// sampleReport is trimmed from `trivy image --server ... --format json` output.
// It covers the shapes the parser has to survive: an OS package result, a
// language-specific result, a secret result carrying no Vulnerabilities key at
// all, and a result whose Vulnerabilities is explicitly null.
const sampleReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "nginx:1.19.1",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "nginx:1.19.1 (debian 10.4)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-1000", "PkgName": "openssl", "InstalledVersion": "1.1.1d", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2020-1001", "PkgName": "openssl", "InstalledVersion": "1.1.1d", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2020-1002", "PkgName": "curl", "InstalledVersion": "7.64.0", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2020-1003", "PkgName": "bash", "InstalledVersion": "5.0", "Severity": "MEDIUM"},
        {"VulnerabilityID": "CVE-2020-1004", "PkgName": "perl", "InstalledVersion": "5.28", "Severity": "LOW"},
        {"VulnerabilityID": "CVE-2020-1005", "PkgName": "tar", "InstalledVersion": "1.30", "Severity": "UNKNOWN"}
      ]
    },
    {
      "Target": "app/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-2000", "PkgName": "lodash", "InstalledVersion": "4.17.15", "Severity": "critical"},
        {"VulnerabilityID": "CVE-2021-2001", "PkgName": "minimist", "InstalledVersion": "1.2.0", "Severity": "Medium"}
      ]
    },
    {
      "Target": "nginx:1.19.1",
      "Class": "secret"
    },
    {
      "Target": "app/empty",
      "Class": "lang-pkgs",
      "Vulnerabilities": null
    }
  ]
}`

func TestCountSeveritiesFromTrivyJSON(t *testing.T) {
	var report TrivyReport
	if err := json.Unmarshal([]byte(sampleReport), &report); err != nil {
		t.Fatalf("unmarshalling sample report: %v", err)
	}

	if len(report.Results) != 4 {
		t.Fatalf("parsed %d results, want 4", len(report.Results))
	}

	counts := countSeverities(report)
	want := map[string]int{
		"CRITICAL": 2, // one uppercase, one lowercase
		"HIGH":     2,
		"MEDIUM":   2, // one uppercase, one mixed case
		"LOW":      1,
		"UNKNOWN":  1,
	}
	for severity, wantCount := range want {
		if counts[severity] != wantCount {
			t.Errorf("counts[%q] = %d, want %d", severity, counts[severity], wantCount)
		}
	}
}

func TestCountSeveritiesEmptyReport(t *testing.T) {
	counts := countSeverities(TrivyReport{})

	// Every severity must be present and zeroed, so table cells never render empty.
	for _, severity := range severities {
		if count, ok := counts[severity]; !ok || count != 0 {
			t.Errorf("counts[%q] = %d (present=%t), want 0 (present=true)", severity, count, ok)
		}
	}
}

func TestCountSeveritiesUnrecognizedSeverityFallsBackToUnknown(t *testing.T) {
	report := TrivyReport{Results: []TrivyResult{{
		Vulnerabilities: []Vulnerability{
			{VulnerabilityID: "CVE-1", Severity: "NEGLIGIBLE"},
			{VulnerabilityID: "CVE-2", Severity: ""},
		},
	}}}

	counts := countSeverities(report)
	if counts["UNKNOWN"] != 2 {
		t.Errorf("counts[UNKNOWN] = %d, want 2", counts["UNKNOWN"])
	}
}

func TestSortVulResults(t *testing.T) {
	results := []vulResult{
		{image: "low-only", low: 9, supported: true},
		{image: "unscannable", critical: -1, high: -1, med: -1, low: -1, unknown: -1},
		{image: "one-critical", critical: 1, supported: true},
		{image: "many-high", high: 40, supported: true},
		{image: "clean", supported: true},
		{image: "two-critical", critical: 2, high: 1, supported: true},
	}

	sortVulResults(results)

	want := []string{"two-critical", "one-critical", "many-high", "low-only", "clean", "unscannable"}
	for i, name := range want {
		if results[i].image != name {
			got := make([]string, len(results))
			for j, r := range results {
				got[j] = r.image
			}
			t.Fatalf("sorted order = %v, want %v", got, want)
		}
	}
}

// pod builds a fixture with the three container lists, so image discovery can be
// tested without an API server.
func pod(name string, main, init, ephemeral []string) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name}}
	for _, image := range main {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{
			Name:  "main-" + image,
			Image: image,
		})
	}
	for _, image := range init {
		p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{
			Name:  "init-" + image,
			Image: image,
		})
	}
	for _, image := range ephemeral {
		p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name:  "debug-" + image,
				Image: image,
			},
		})
	}
	return p
}

func TestImagesFromPodsCoversAllContainerTypes(t *testing.T) {
	pods := []corev1.Pod{pod("web", []string{"nginx:1.19.1"}, []string{"busybox:1.36"}, []string{"debug:latest"})}

	got := imagesFromPods(pods)

	want := map[string]string{
		"nginx:1.19.1": "web",
		"busybox:1.36": "web",
		"debug:latest": "web",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d images (%v), want %d", len(got), got, len(want))
	}
	for image, wantPods := range want {
		if got[image] != wantPods {
			t.Errorf("images[%q] = %q, want %q", image, got[image], wantPods)
		}
	}
}

func TestImagesFromPodsJoinsSharedImageInSortedOrder(t *testing.T) {
	// Deliberately out of alphabetical order: the output must not depend on input
	// order or on Go's randomized map iteration.
	pods := []corev1.Pod{
		pod("web-c", []string{"nginx:1.19.1"}, nil, nil),
		pod("web-a", []string{"nginx:1.19.1"}, nil, nil),
		pod("web-b", []string{"nginx:1.19.1"}, nil, nil),
	}

	for i := 0; i < 20; i++ {
		if got := imagesFromPods(pods)["nginx:1.19.1"]; got != "web-a,web-b,web-c" {
			t.Fatalf("images[nginx:1.19.1] = %q, want %q", got, "web-a,web-b,web-c")
		}
	}
}

func TestImagesFromPodsListsPodOnceForRepeatedImage(t *testing.T) {
	// Same image in a main container, an init container and an ephemeral container
	// of a single pod: the pod is named once, with no trailing separator.
	pods := []corev1.Pod{pod("multi", []string{"alpine:3.18", "alpine:3.18"}, []string{"alpine:3.18"}, []string{"alpine:3.18"})}

	got := imagesFromPods(pods)["alpine:3.18"]

	if got != "multi" {
		t.Errorf("images[alpine:3.18] = %q, want %q", got, "multi")
	}
}

func TestImagesFromPodsWithOnlyMainContainers(t *testing.T) {
	pods := []corev1.Pod{
		pod("web", []string{"nginx:1.19.1"}, nil, nil),
		pod("cache", []string{"redis:6.0-alpine"}, nil, nil),
	}

	got := imagesFromPods(pods)

	want := map[string]string{"nginx:1.19.1": "web", "redis:6.0-alpine": "cache"}
	if len(got) != len(want) {
		t.Fatalf("got %d images (%v), want %d", len(got), got, len(want))
	}
	for image, wantPods := range want {
		if got[image] != wantPods {
			t.Errorf("images[%q] = %q, want %q", image, got[image], wantPods)
		}
	}
}

func TestImagesFromPodsIgnoresEmptyImageAndNoPods(t *testing.T) {
	if got := imagesFromPods(nil); len(got) != 0 {
		t.Errorf("imagesFromPods(nil) = %v, want empty", got)
	}

	// An ephemeral container spec can carry an empty image; it must not become a
	// scan target.
	got := imagesFromPods([]corev1.Pod{pod("odd", []string{""}, nil, []string{""})})
	if len(got) != 0 {
		t.Errorf("imagesFromPods with empty images = %v, want empty", got)
	}
}

func TestDefaultKubeconfig(t *testing.T) {
	tests := []struct {
		name string
		env  string
		home string
		want string
	}{
		// Regression: KUBE_CONFIG used to be consulted only when homedir was
		// empty, so it was silently ignored on any normal machine.
		{"env wins over home", "/custom/kubeconfig", "/home/user", "/custom/kubeconfig"},
		{"home used when env unset", "", "/home/user", "/home/user/.kube/config"},
		{"env used when home empty", "/custom/kubeconfig", "", "/custom/kubeconfig"},
		{"empty when neither set", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultKubeconfig(tt.env, tt.home); got != tt.want {
				t.Errorf("defaultKubeconfig(%q, %q) = %q, want %q", tt.env, tt.home, got, tt.want)
			}
		})
	}
}

func TestDefaultServer(t *testing.T) {
	if got := defaultServer("trivy.internal:8080"); got != "trivy.internal:8080" {
		t.Errorf("defaultServer with env = %q, want %q", got, "trivy.internal:8080")
	}
	if got := defaultServer(""); got != "127.0.0.1:8080" {
		t.Errorf("defaultServer without env = %q, want %q", got, "127.0.0.1:8080")
	}
}
