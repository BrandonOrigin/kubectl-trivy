/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
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
	Long:  "Scan pods' image via Trivy in the namespace",
	// Uncomment the following line if your bare application
	// has an action associated with it:
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

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.kubectl-trivy.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	defaultKubeConfig := ""
	if home := homedir.HomeDir(); home != "" {
		defaultKubeConfig = filepath.Join(home, ".kube", "config")
	} else if os.Getenv("KUBE_CONFIG") != "" {
		defaultKubeConfig = os.Getenv("KUBE_CONFIG")
	}
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", defaultKubeConfig, "Absolute path to the kubeconfig file")
	rootCmd.Flags().StringP("namespace", "n", "default", "namespace")

	defaultTrivyServer := "127.0.0.1:8080"
	if os.Getenv("TRIVY_SERVER") != "" {
		defaultTrivyServer = os.Getenv("TRIVY_SERVER")
	}

	rootCmd.Flags().StringVarP(&trivyServer, "server", "s", defaultTrivyServer, "Remote Trivy Address. (default 127.0.0.1:8080) ")
}
