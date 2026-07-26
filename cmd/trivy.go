package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type vulResult struct {
	image   string
	pods    string
	high    int
	med     int
	low     int
	unknow  int
	support bool
}

func getImages(namespace string) map[string]string {

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// Get pods in the namespace
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	images := map[string]string{}
	if errors.IsNotFound(err) {
		fmt.Printf("namespace %s not found\n", namespace)
	} else if err != nil {
		panic(err.Error())
	} else {
		fmt.Printf("Found %d podin namespace %s\n", len(pods.Items), namespace)
		if len(pods.Items) > 0 {
			for _, pod := range pods.Items {
				for _, container := range pod.Spec.Containers {
					images[container.Image] = pod.Name + "," + images[container.Image]
				}
			}
		}
	}
	return images
}

func showScanResult(images map[string]string) {

	// for each image, scan it via trivy fmt.Println(trivy)

	imgVulResults := []vulResult{}
	for img, pods := range images {

		// cmd := "trivy client --remote http://" + trivy["server"] + ":" + trivy["port"] + " " + img + " | grep 'Total'"
		// out, err := exec.Command("bash", "-c", cmd).Output()
		cmd1 := "trivy client --format json --remote http://" + trivyServer + " " + img
		parseResultCmd := cmd1 + " | jq -r \".Results[]\""
		_, err1 := exec.Command("bash", "-c", parseResultCmd).Output()

		if err1 != nil {
			fmt.Println("Failed to execute command:", cmd1)
			//t.AppendRow([]interface{}{img, -1, -1, -1, -1, "Unsupported"})
			imgVulResults = append(imgVulResults, vulResult{img, pods, -1, -1, -1, -1, false})
			continue
		}

		cmd2 := cmd1 + " | jq -r \".Results[].Vulnerabilities[].Severity\""
		out2, err2 := exec.Command("bash", "-c", cmd2).Output()
		if err2 != nil {
			fmt.Println("No Vulnerabilities:", img)
			//t.AppendRow([]interface{}{img, 0, 0, 0, 0})
			imgVulResults = append(imgVulResults, vulResult{img, pods, 0, 0, 0, 0, true})
		} else {
			splitFn := func(c rune) bool {
				return c == '\n'
			}
			severity := strings.FieldsFunc(string(out2), splitFn)
			//fmt.Println(img, ":", severity)
			vulCount := countOccurence(severity)
			//t.AppendRow([]interface{}{img, vulCount["HIGH"], vulCount["MEDIUM"], vulCount["LOW"], vulCount["UNKNOWN"]})
			imgVulResults = append(imgVulResults, vulResult{img, pods, vulCount["HIGH"], vulCount["MEDIUM"], vulCount["LOW"], vulCount["UNKNOWN"], true})
		}

		// t.AppendSeparator()
	}

	sort.Slice(imgVulResults, func(i, j int) bool {
		if imgVulResults[i].high != imgVulResults[j].high {
			return imgVulResults[i].high > imgVulResults[j].high
		} else if imgVulResults[i].med != imgVulResults[j].med {
			return imgVulResults[i].med > imgVulResults[j].med
		} else if imgVulResults[i].low != imgVulResults[j].low {
			return imgVulResults[i].low > imgVulResults[j].low
		}
		return imgVulResults[i].unknow > imgVulResults[j].unknow

	})

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Image", "Pods", "High", "Medium", "Low", "Unknow"})
	for _, r := range imgVulResults {
		// fmt.Println(value.image, value.h, value.m, value.l)
		if r.support {
			t.AppendRow([]interface{}{r.image, r.pods, r.high, r.med, r.low, r.unknow})
		} else {
			t.AppendRow([]interface{}{r.image, r.pods, r.high, r.med, r.low, r.unknow, "Unsupported"})
		}
	}
	t.Render()

}

func countOccurence(apps []string) map[string]int {
	dict := make(map[string]int)
	for _, v := range apps {
		dict[v]++
	}
	return dict
}
