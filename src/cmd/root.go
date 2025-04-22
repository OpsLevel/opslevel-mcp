package cmd

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/opslevel/opslevel-go/v2025"

	"github.com/spf13/cobra"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type NullArguments struct{}

type LightweightComponent struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
	URL   string `json:"url"`
}

type LightweightInfrastructureResource struct {
	Id           string   `json:"id"`
	Name         string   `json:"name"`
	Owner        string   `json:"owner"`
	Aliases      []string `json:"aliases"`
	Schema       string   `json:"schema"`
	ProviderType string   `json:"providerType"`
}

// NewToolResult creates a CallToolResult for the passed object handling any json marshaling errors
func NewToolResult(obj any) (*mcp.CallToolResult, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(data)), nil
}

var rootCmd = &cobra.Command{
	Use:   "opslevel-mcp",
	Short: "Opslevel MCP Server",
	Long:  `Opslevel MCP Server`,

	RunE: func(cmd *cobra.Command, args []string) error {
		s := server.NewMCPServer(
			"OpsLevel",
			version,
		)

		client := NewGraphClient(version)

		// Register Teams
		s.AddTool(
			mcp.NewTool("teams",
				mcp.WithDescription("Get all the team names, identifiers and metadata for the opslevel account.  Teams are owners of other objects in opslevel. Only use this if you need to search all teams.")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListTeams(nil)
				if err != nil {
					return nil, err
				}
				return NewToolResult(resp.Nodes)
			})

		// Register Users
		s.AddTool(
			mcp.NewTool("users", mcp.WithDescription("Get all the user names, e-mail addresses and metadata for the opslevel account.  Users are the people in opslevel. Only use this if you need to search all users.")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListUsers(nil)
				if err != nil {
					return nil, err
				}
				return NewToolResult(resp.Nodes)
			})

		// Register Actions
		s.AddTool(
			mcp.NewTool("actions", mcp.WithDescription("Get all the information about actions the user can run in the opslevel account")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListTriggerDefinitions(nil)
				if err != nil {
					return nil, err
				}
				return NewToolResult(resp.Nodes)
			})

		// Register Filters
		s.AddTool(
			mcp.NewTool("filters", mcp.WithDescription("Get all the rubric filter names and which predicates they have for the opslevel account")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListFilters(nil)
				if err != nil {
					return nil, err
				}
				return NewToolResult(resp.Nodes)
			})

		// Register Components
		s.AddTool(
			mcp.NewTool("components", mcp.WithDescription("Get all the components in the opslevel account.  Components are objects in opslevel that represent things like apis, libraries, services, frontends, backends, etc.")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListServices(nil)
				if err != nil {
					return nil, err
				}
				var components []LightweightComponent
				for _, node := range resp.Nodes {
					components = append(components, LightweightComponent{
						Id:    string(node.Id),
						Name:  node.Name,
						Owner: node.Owner.Alias,
						URL:   node.HtmlURL,
					})
				}
				return NewToolResult(components)
			})

		// Register Infra
		s.AddTool(
			mcp.NewTool("infrastructure", mcp.WithDescription("Get all the infrastructure in the opslevel account.  Infrastructure are objects in opslevel that represent cloud provider resources like vpc, databases, caches, networks, vms, etc.")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListInfrastructure(nil)
				if err != nil {
					return nil, err
				}
				var infrastructureResources []LightweightInfrastructureResource
				for _, node := range resp.Nodes {
					infrastructureResources = append(infrastructureResources, LightweightInfrastructureResource{
						Id:           string(node.Id),
						Name:         node.Name,
						Owner:        node.Owner.Alias(),
						Aliases:      node.Aliases,
						Schema:       node.Schema,
						ProviderType: node.ProviderType,
					})
				}
				return NewToolResult(infrastructureResources)
			})

		// Register Domains
		s.AddTool(
			mcp.NewTool("domains", mcp.WithDescription("Get all the domains in the opslevel account.  Domains are objects in opslevel that represent a top-level abstraction used to organize and categorize software systems.")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListDomains(nil)
				if err != nil {
					return nil, err
				}
				return NewToolResult(resp.Nodes)
			})

		// Register Systems
		s.AddTool(
			mcp.NewTool("systems", mcp.WithDescription("Get all the systems in the opslevel account.  Systems are objects in opslevel that represent a grouping of services or components that act together to serve a business function or process.")),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListSystems(nil)
				if err != nil {
					return nil, err
				}
				return NewToolResult(resp.Nodes)
			})

		// Register ability to fetch a single resource by ID or alias
		s.AddTool(
			mcp.NewTool(
				"resourceDetails",
				mcp.WithDescription("Get details for a single resource in an OpsLevel account using its ID or alias."),
				mcp.WithString("resourceType", mcp.Required(), mcp.Description("The type of the resource."), mcp.Enum("service", "infrastructure_resource", "team", "system", "domain")),
				mcp.WithString("identifier", mcp.Required(), mcp.Description("The ID or alias of the resource.")),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resourceTypeString := req.Params.Arguments["resourceType"].(string)
				identifier := req.Params.Arguments["identifier"].(string)
				resourceType := opslevel.AliasOwnerTypeEnum(resourceTypeString)
				resp, err := client.GetAliasableResource(resourceType, identifier)
				if err != nil {
					return nil, err
				}
				return NewToolResult(resp)
			})

		log.Info().Msg("Starting MCP server...")
		if err := server.ServeStdio(s); err != nil {
			if err == context.Canceled {
				log.Info().Msg("MCP server stdio connection closed.")
			} else {
				log.Error().Err(err).Msg("MCP server error")
			}
		}

		return nil
	},
}

func Execute(v string, currentCommit string) {
	version = v
	commit = currentCommit
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().String("log-format", "TEXT", "overrides environment variable 'OPSLEVEL_LOG_FORMAT' (options [\"JSON\", \"TEXT\"])")
	rootCmd.PersistentFlags().String("log-level", "INFO", "overrides environment variable 'OPSLEVEL_LOG_LEVEL' (options [\"ERROR\", \"WARN\", \"INFO\", \"DEBUG\"])")
	rootCmd.PersistentFlags().String("api-url", "https://app.opslevel.com", "The OpsLevel API Url. Overrides environment variable 'OPSLEVEL_API_URL'")
	rootCmd.PersistentFlags().String("api-token", "", "The OpsLevel API Token. Overrides environment variable 'OPSLEVEL_API_TOKEN'")
	rootCmd.PersistentFlags().Int("api-timeout", 10, "The number of seconds to timeout of the request. Overrides environment variable 'OPSLEVEL_API_TIMEOUT'")

	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.BindEnv("log-format", "OPSLEVEL_LOG_FORMAT", "OL_LOG_FORMAT", "OL_LOGFORMAT")
	viper.BindEnv("log-level", "OPSLEVEL_LOG_LEVEL", "OL_LOG_LEVEL", "OL_LOGLEVEL")
	viper.BindEnv("api-url", "OPSLEVEL_API_URL", "OL_API_URL", "OPSLEVEL_APP_URL", "OL_APP_URL")
	viper.BindEnv("api-token", "OPSLEVEL_API_TOKEN", "OL_API_TOKEN", "OL_APITOKEN")
	viper.BindEnv("api-timeout", "OPSLEVEL_API_TIMEOUT")
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetEnvPrefix("OPSLEVEL")
	viper.AutomaticEnv()
	setupLogging()
}

func setupLogging() {
	logFormat := strings.ToLower(viper.GetString("log-format"))
	logLevel := strings.ToLower(viper.GetString("log-level"))

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if logFormat == "text" {
		output := zerolog.ConsoleWriter{Out: os.Stderr}
		log.Logger = log.Output(output)
	}

	switch {
	case logLevel == "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case logLevel == "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case logLevel == "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
