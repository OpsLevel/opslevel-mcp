package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

type Build struct {
	Version string `json:"version,omitempty"`
	Commit  string `json:"git,omitempty"`
	GoInfo  GoInfo `json:"go,omitempty"`
}

type OpslevelVersion struct {
	Commit  string `json:"app_commit,omitempty"`
	Version string `json:"app_version,omitempty"`
}

type GoInfo struct {
	Version  string `json:"version,omitempty"`
	Compiler string `json:"compiler,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

var (
	shortVersionFlag bool
	version          = "development"
	commit           = "none"
	build            Build
)

func initBuild() {
	build.Version = version
	if len(commit) >= 12 {
		build.Commit = commit[:12]
	} else {
		build.Commit = commit
	}

	build.GoInfo = getGoInfo()
}

func getGoInfo() GoInfo {
	return GoInfo{
		Version:  runtime.Version(),
		Compiler: runtime.Compiler,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print version information`,
	RunE:  runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.PersistentFlags().BoolVar(&shortVersionFlag, "short", false, "Print only version number")
}

func runVersion(cmd *cobra.Command, args []string) error {
	if shortVersionFlag {
		fmt.Printf("%s-%s\n", version, commit)
		return nil
	}
	initBuild()
	versionInfo, err := json.MarshalIndent(build, "", "    ")
	if err != nil {
		return err
	}
	fmt.Println(string(versionInfo))
	return nil
}
