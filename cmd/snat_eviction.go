package cmd

import (
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/kakao/kubectl-cilium/internal/scanner"
	"os"
)

var snatEvicitonCmd = &cobra.Command{
	Use:   "snat-eviction",
	Short: "Detect nodes at risk of SNAT map eviction",
	Long: `Analyze cluster nodes to identify those at risk of SNAT map eviction issue.

This command checks for conditions that could lead to SNAT map high eviction rates,
such as a large number of active connections. If any nodes are identified as being at risk,
it is recommended to perform a drain and reboot operation on them.

For more details, please refer to: https://github.com/cilium/cilium/pull/37747

Examples:
  # Check for SNAT eviction risks across all nodes
  kubectl-cilium snat-eviction
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		confirm := false
		prompt := &survey.Confirm{
			Message: "Do you want to continue?",
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
		s, err := scanner.NewScanner(nil, nil, kubeconfig)
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
	rootCmd.AddCommand(snatEvicitonCmd)
}
