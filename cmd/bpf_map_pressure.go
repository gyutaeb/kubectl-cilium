package cmd

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/kakao/kubectl-cilium/internal/pressure"

	"github.com/spf13/cobra"
)

var bpfMapPressureCmd = &cobra.Command{
	Use:   "bpf-map-pressure",
	Short: "Check BPF map pressure across all nodes",
	Long: `Analyze cluster nodes to identify BPF map pressure by checking core BPF maps under /sys/fs/bpf/tc/globals.

This command check the usage of core BPF maps used by Cilium.
It will show the current usage and maximum capacity of each map, helping identify
potential pressure points in the BPF map system.

Example:
  # Check BPF map pressure across all nodes
  kubectl-cilium bpf-map-pressure

  # Check BPF map pressure for a specific node
  kubectl-cilium bpf-map-pressure --nodename=node-1
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		confirm := false
		prompt := &survey.Confirm{
			Message: `This command create inspector pods on all nodes to check BPF map pressure. And it may consume CPU resource (200m core limit)
Do you want to continue?`,
		}
		err := survey.AskOne(prompt, &confirm)
		if err != nil {
			return err
		}
		if !confirm {
			fmt.Println("Aborted.")
			os.Exit(0)
		}

		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		nodeName, _ := cmd.Flags().GetString("nodename")

		s, err := pressure.NewScanner(nil, nil, kubeconfig)
		if err != nil {
			return err
		}
		err = s.Validate()
		if err != nil {
			return err
		}
		return s.Run(nodeName)
	},
}

func init() {
	rootCmd.AddCommand(bpfMapPressureCmd)
}
