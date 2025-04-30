package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "kubectl-cilium",
	Annotations: map[string]string{
		cobra.CommandDisplayNameAnnotation: "kubectl cilium",
	},
	Short: "Diagnostic tool for Cilium",
	Long:  `Diagnostic tool for Cilium`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("kubeconfig", "k", "", "Path to kubeconfig file")
	rootCmd.PersistentFlags().StringP("nodename", "n", "", "Node name")
}
