package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"k8s.io/client-go/util/homedir"
)

var kubeconfig string
var trivyServer string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "kubectl-trivy",
	Short: "Scan pods' image via Trivy in the namespace",
	Long: "Scan every container image running in a Kubernetes namespace against a remote Trivy\n" +
		"server, and report vulnerability counts per image sorted by severity.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		ns, err := cmd.Flags().GetString("namespace")
		if err != nil {
			return fmt.Errorf("reading namespace flag: %w", err)
		}

		ctx := cmd.Context()
		images, err := getImages(ctx, ns)
		if err != nil {
			return err
		}

		fmt.Println("Remote Trivy Server: ", trivyServer)
		return showScanResult(ctx, images)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// Cancel the command context on SIGINT/SIGTERM so in-flight `trivy` processes
	// are torn down instead of being left behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

// defaultKubeconfig resolves the kubeconfig path used when --kubeconfig is not
// given: KUBE_CONFIG wins if set, otherwise ~/.kube/config.
func defaultKubeconfig(env, home string) string {
	if env != "" {
		return env
	}
	if home != "" {
		return filepath.Join(home, ".kube", "config")
	}
	return ""
}

// defaultServer resolves the Trivy server address used when --server is not
// given: TRIVY_SERVER if set, otherwise localhost.
func defaultServer(env string) string {
	if env != "" {
		return env
	}
	return "127.0.0.1:8080"
}

func init() {
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig",
		defaultKubeconfig(os.Getenv("KUBE_CONFIG"), homedir.HomeDir()),
		"Absolute path to the kubeconfig file (overrides $KUBE_CONFIG)")
	rootCmd.Flags().StringP("namespace", "n", "default", "Kubernetes namespace to scan")
	rootCmd.Flags().StringVarP(&trivyServer, "server", "s",
		defaultServer(os.Getenv("TRIVY_SERVER")),
		"Remote Trivy server address (overrides $TRIVY_SERVER)")
}
