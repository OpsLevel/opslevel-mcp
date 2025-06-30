package cmd

import (
	"fmt"
	"time"

	"github.com/opslevel/opslevel-go/v2025"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewGraphClient(version string, options ...opslevel.Option) *opslevel.Client {
	timeout := time.Second * time.Duration(viper.GetInt("api-timeout"))
	api_token := viper.GetString("api-token")
	options = append(
		options,
		opslevel.SetAPIToken(api_token),
		opslevel.SetURL(viper.GetString("api-url")),
		opslevel.SetTimeout(timeout),
		opslevel.SetUserAgentExtra(fmt.Sprintf("mcp-%s", version)),
	)
	client := opslevel.NewGQLClient(options...)

	// If API token is provided, ensure it's valid in OpsLevel to notify the user.
	// If no token is provided, just allow the server to start for inspection.
	if api_token != "" {
		clientErr := client.Validate()
		cobra.CheckErr(clientErr)
	}

	return client
}
