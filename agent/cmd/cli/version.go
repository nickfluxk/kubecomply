package main

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// These variables are set by ldflags during build.
var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

type versionInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"gitCommit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

func newVersionCmd() *cobra.Command {
	var outputJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show KubeComply version information",
		Long:  "Display the version, git commit, build date, and Go runtime information for the KubeComply CLI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := versionInfo{
				Version:   version,
				GitCommit: gitCommit,
				BuildDate: buildDate,
				GoVersion: runtime.Version(),
				Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			}

			if outputJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "KubeComply CLI\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  Version:    %s\n", info.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "  Git Commit: %s\n", info.GitCommit)
			fmt.Fprintf(cmd.OutOrStdout(), "  Build Date: %s\n", info.BuildDate)
			fmt.Fprintf(cmd.OutOrStdout(), "  Go Version: %s\n", info.GoVersion)
			fmt.Fprintf(cmd.OutOrStdout(), "  Platform:   %s\n", info.Platform)
			return nil
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output version information as JSON")

	return cmd
}
