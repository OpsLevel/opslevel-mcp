package cmd

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	ol "github.com/opslevel/opslevel-go/v2025"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type NullArguments struct{}

func registerListTool[T ol.Connection](s *server.MCPServer, fn func(variables *ol.PayloadVariables) (T, error), name string, description string) {
	s.AddTool(
		mcp.NewTool(name, mcp.WithDescription(description)),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resp, err := fn(nil)
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(resp.GetNodes())
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText(string(data)), nil
		})
}

var mcpCmd = &cobra.Command{
	Use:   "run",
	Short: "Runs MCP Server",
	Long:  "Runs MCP Server",

	RunE: func(cmd *cobra.Command, args []string) error {
		done := make(chan struct{})

		s := server.NewMCPServer(
			"OpsLevel",
			version,
		)

		client := NewGraphClient(version)

		// Register Teams
		registerListTool(s, client.ListTeams, "Teams", "Get all the team names, identifiers and metadata for the opslevel account.  Teams are owners of other objects in opslevel. Only use this if you need to search all teams.")
		registerListTool(s, client.ListUsers, "Users", "Get all the user names, e-mail addresses and metadata for the opslevel account.  Users are the people in opslevel. Only use this if you need to search all users.")
		registerListTool(s, client.ListTriggerDefinitions, "Triggers", "Get all the information about actions the user can run in the opslevel account.")
		registerListTool(s, client.ListFilters, "Filters", "Get all the rubric filter names and which predicates they have for the opslevel account.")
		registerListTool(s, client.ListInfrastructure, "Infrastructure", "Get all the infrastructure in the opslevel account.  Infrastructure are objects in opslevel that represent cloud provider resources like vpc, databases, caches, networks, vms, etc.")
		registerListTool(s, client.ListDomains, "Domains", "Get all the domains in the opslevel account.  Domains are objects in opslevel that represent a top-level abstraction used to organize and categorize software systems.")
		registerListTool(s, client.ListSystems, "Systems", "Get all the systems in the opslevel account.  Systems are objects in opslevel that represent things like apis, libraries, services, frontends, backends, etc.")
		registerListTool(s, client.ListServices, "Components", "Get all the components in the opslevel account.  Components are objects in opslevel that represent things like apis, libraries, services, frontends, backends, etc.")

		log.Info().Msg("Starting MCP server...")
		if err := server.ServeStdio(s); err != nil {
			panic(err)
		}
		<-done

		return nil
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
