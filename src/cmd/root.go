package cmd

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/opslevel/opslevel-go/v2025"

	"github.com/spf13/cobra"

	"github.com/relvacode/iso8601"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

//go:embed default_prompt.md
var defaultSystemPrompt string

type serializedComponent struct {
	Id        string
	Framework string
	Language  string
	Name      string
	Owner     string
	Url       string
	Level     serializedLevel
	Lifecycle serializedLifecycle
	Tier      serializedTier
}

type serializedInfrastructureResource struct {
	Id           string
	Name         string
	Owner        string
	Aliases      []string
	Schema       string
	ProviderType string
}

type serializedLevel struct {
	Alias string
	Index int
}

type serializedLifecycle struct {
	Alias string
	Index int
}

type serializedTier struct {
	Alias string
	Index int
}

type serializedCheck struct {
	Id          string
	Name        string
	Owner       string
	Description string
	Notes       string
	Enabled     bool
	Type        string
	Level       serializedLevel
	Category    string
}

type serializedCheckResult struct {
	CheckId     string
	CheckName   string
	Message     string
	Status      string
	LastUpdated iso8601.Time
}

type serializedCheckResultsByLevel struct {
	Level        serializedLevel
	CheckResults []serializedCheckResult
}

type serializedCheckResults struct {
	ByLevel      []serializedCheckResultsByLevel
	CurrentLevel serializedLevel
	NextLevel    *serializedLevel
}

type serializedCampaign struct {
	Id           string
	Name         string
	ProjectBrief string
	Status       string
	CheckStats   opslevel.Stats
	HtmlURL      string
	ServiceStats opslevel.Stats
	Filter       *opslevel.FilterId
	Owner        *opslevel.TeamId
	StartDate    *iso8601.Time
	EndedDate    *iso8601.Time
	TargetDate   *iso8601.Time
	Reminder     *opslevel.CampaignReminder
}

// AccountMetadata represents the different types of account metadata that can be fetched
type AccountMetadata string

// Available metadata types
const (
	AccountMetadataLifecycles     AccountMetadata = "lifecycles"
	AccountMetadataLevels         AccountMetadata = "levels"
	AccountMetadataTiers          AccountMetadata = "tiers"
	AccountMetadataComponentTypes AccountMetadata = "componentTypes"
)

// AllAccountMetadataStrings returns a slice of all available metadata types as strings
func AllAccountMetadataStrings() []string {
	types := []AccountMetadata{
		AccountMetadataLifecycles,
		AccountMetadataLevels,
		AccountMetadataTiers,
		AccountMetadataComponentTypes,
	}

	result := make([]string, len(types))
	for i, t := range types {
		result[i] = string(t)
	}
	return result
}

// newToolResult creates a CallToolResult for the passed object handling any json marshaling errors
func newToolResult(obj any, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return mcp.NewToolResultErrorFromErr("operation failed", err), nil
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("failed to marshal response", err), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

var rootCmd = &cobra.Command{
	Use:   "opslevel-mcp",
	Short: "Opslevel MCP Server",
	Long:  `Opslevel MCP Server`,

	RunE: func(cmd *cobra.Command, args []string) error {
		token := viper.GetString("api-token")
		// Allow server to start even if token is missing
		if token == "" {
			log.Warn().Msg("No API token was found. Tool requests will fail with 401 Unauthorized. Set an API token using --api-token=XXX or the OPSLEVEL_API_TOKEN environment variable.")
		}

		s := server.NewMCPServer(
			"OpsLevel",
			version,
			server.WithInstructions(defaultSystemPrompt),
		)

		client := NewGraphClient(version)

		trueValue := true
		falseValue := false

		// Register Teams
		s.AddTool(
			mcp.NewTool(
				"teams",
				mcp.WithDescription("Get all team names, contact methods, and metadata for the OpsLevel account. Teams are owners of other objects in OpsLevel. Provide searchTerm when looking for a specific team by name."),
				mcp.WithString("searchTerm", mcp.Description("The name of the team to search for. Partial matches are returned. Case insensitive.")),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Teams in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				searchTerm := req.GetString("searchTerm", "")
				resp, err := client.SearchTeams(searchTerm, nil)

				return newToolResult(resp.Nodes, err)
			})

		// Register Users
		s.AddTool(
			mcp.NewTool(
				"users",
				mcp.WithDescription("Get all the user names, e-mail addresses and metadata for the OpsLevel account.  Users are the people in OpsLevel. Only use this if you need to search all users."),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Users in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListUsers(nil)
				return newToolResult(resp.Nodes, err)
			})

		// Register Actions
		s.AddTool(
			mcp.NewTool(
				"actions",
				mcp.WithDescription("Get all the information about actions the user can run in the OpsLevel account"),

				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Actions in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListTriggerDefinitions(nil)
				return newToolResult(resp.Nodes, err)
			})

		// Register Filters
		s.AddTool(
			mcp.NewTool(
				"filters",
				mcp.WithDescription("Get all the rubric filter names and which predicates they have for the OpsLevel account"),

				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Filters in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListFilters(nil)
				return newToolResult(resp.Nodes, err)
			})

		// Register Components
		s.AddTool(
			mcp.NewTool(
				"components",
				mcp.WithDescription("Get all the components in the OpsLevel account.  Components are objects in OpsLevel that represent things like apis, libraries, services, frontends, backends, etc. Use this tool to list what components are in the catalog, what team is the owner, what primary coding language is used, and what primary framework is used. It also includes its rubric level, corresponding to the maturity of the component; a higher index is better. A level is achieved by passing all checks tied to that same level. The Lifecycle field indicates the stage of the component (e.g., Alpha, Beta, GA, Decommissioned). The Tier field represents the importance and criticality of the component, with Tier 1 being the most critical (customer-facing with high impact) and Tier 4 being of least importance."),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Components in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListServices(nil)
				if err != nil || resp == nil {
					return mcp.NewToolResultErrorFromErr("failed to list components", err), nil
				}
				var components []serializedComponent
				for _, node := range resp.Nodes {
					components = append(components, serializedComponent{
						Id:        string(node.Id),
						Name:      node.Name,
						Owner:     node.Owner.Alias,
						Language:  node.Language,
						Framework: node.Framework,
						Url:       node.HtmlURL,
						Level:     serializedLevel{Alias: node.MaturityReport.OverallLevel.Alias, Index: node.MaturityReport.OverallLevel.Index},
						Lifecycle: serializedLifecycle{Alias: node.Lifecycle.Alias, Index: node.Lifecycle.Index},
						Tier:      serializedTier{Alias: node.Tier.Alias, Index: node.Tier.Index},
					})
				}
				return newToolResult(components, nil)
			})

		// Register Infra
		s.AddTool(
			mcp.NewTool(
				"infrastructure",
				mcp.WithDescription("Get all the infrastructure in the OpsLevel account.  Infrastructure are objects in OpsLevel that represent cloud provider resources like vpc, databases, caches, networks, vms, etc."),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Infrastructure in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListInfrastructure(nil)
				if err != nil {
					return mcp.NewToolResultErrorFromErr("failed to list infrastructure", err), nil
				}
				var infrastructureResources []serializedInfrastructureResource
				for _, node := range resp.Nodes {
					infrastructureResources = append(infrastructureResources, serializedInfrastructureResource{
						Id:           string(node.Id),
						Name:         node.Name,
						Owner:        node.Owner.Alias(),
						Aliases:      node.Aliases,
						Schema:       node.Schema,
						ProviderType: node.ProviderType,
					})
				}
				return newToolResult(infrastructureResources, nil)
			})

		// Register Domains
		s.AddTool(
			mcp.NewTool(
				"domains",
				mcp.WithDescription("Get all the domains in the OpsLevel account. Domains are comprised of child Systems which contain Components. Used to represent large business units or verticals within OpsLevel."),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Domains in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListDomains(nil)
				return newToolResult(resp.Nodes, err)
			})

		// Register Systems
		s.AddTool(
			mcp.NewTool(
				"systems",
				mcp.WithDescription("Get all the systems in the OpsLevel account. Systems are made up of Components that combine to form a unified whole or function. eg a 'Checkout' System that combines a cart and payment component."),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Systems in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListSystems(nil)
				return newToolResult(resp.Nodes, err)
			})

		// Account metadata is lightweight data often only needed to provide context for other tool calls.
		// We wrap it up in one tool to reduce bloat, but accept a `types` arg to allow the MCP to request what it needs specifically.
		s.AddTool(
			mcp.NewTool(
				"accountMetadata",
				mcp.WithDescription("Get metadata about the OpsLevel account including component types, tiers, & lifecycles, and maturity levels. Use this tool to retrieve relevant context (including indexes and ids for filters) before making other tool calls. Provide `types` whenever possible."),
				mcp.WithArray("types", mcp.Description(fmt.Sprintf("Optional array of specific metadata types to fetch. Valid values: %s. If omitted, all metadata types will be fetched.", strings.Join(AllAccountMetadataStrings(), ", ")))),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Account Metadata in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				// Get requested types from the arguments
				args := req.GetArguments()
				var requestedTypes []any
				if typesArg, exists := args["types"]; exists && typesArg != nil {
					if typesArray, ok := typesArg.([]any); ok {
						requestedTypes = typesArray
					}
				}
				fetchAll := len(requestedTypes) == 0

				// Convert to a map of AccountMetadata type -> bool for lookups
				typesToFetch := make(map[AccountMetadata]bool)

				for _, t := range requestedTypes {
					if typeStr, ok := t.(string); ok {
						typesToFetch[AccountMetadata(typeStr)] = true
					}
				}

				metadata := make(map[string]any)
				var fetchErr error

				// Fetch lifecycles if requested or fetching all
				if fetchAll || typesToFetch[AccountMetadataLifecycles] {
					lifecycles, err := client.ListLifecycles()
					if err != nil && fetchErr == nil {
						fetchErr = fmt.Errorf("failed to list lifecycles: %w", err)
					}
					metadata[string(AccountMetadataLifecycles)] = lifecycles
				}

				// Fetch levels if requested or fetching all
				if fetchAll || typesToFetch[AccountMetadataLevels] {
					levels, err := client.ListLevels(nil)
					if err != nil && fetchErr == nil {
						fetchErr = fmt.Errorf("failed to list levels: %w", err)
					}
					metadata[string(AccountMetadataLevels)] = levels.Nodes
				}

				// Fetch tiers if requested or fetching all
				if fetchAll || typesToFetch[AccountMetadataTiers] {
					tiers, err := client.ListTiers()
					if err != nil && fetchErr == nil {
						fetchErr = fmt.Errorf("failed to list tiers: %w", err)
					}
					metadata[string(AccountMetadataTiers)] = tiers
				}

				// Fetch component types if requested or fetching all
				if fetchAll || typesToFetch[AccountMetadataComponentTypes] {
					componentTypes, err := client.ListComponentTypes(nil)
					if err != nil && fetchErr == nil {
						fetchErr = fmt.Errorf("failed to list component types: %w", err)
					}
					metadata[string(AccountMetadataComponentTypes)] = componentTypes.Nodes
				}

				// Return any metadata we could fetch, along with any error
				return newToolResult(metadata, fetchErr)
			})

		// Register ability to fetch a single resource by ID or alias
		s.AddTool(
			mcp.NewTool(
				"resourceDetails",
				mcp.WithDescription(fmt.Sprintf("Get details for a single resource (%s) in an OpsLevel account using its ID or alias.", strings.Join(opslevel.AllAliasOwnerTypeEnum, ","))),
				mcp.WithString("resourceType", mcp.Required(), mcp.Description("The type of the resource."), mcp.Enum(opslevel.AllAliasOwnerTypeEnum...)),
				mcp.WithString("identifier", mcp.Required(), mcp.Description("The ID or alias of the resource.")),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Resource Details in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resourceTypeString, err := req.RequireString("resourceType")
				if err != nil {
					return mcp.NewToolResultError("resourceType parameter is required"), nil
				}
				identifier, err := req.RequireString("identifier")
				if err != nil {
					return mcp.NewToolResultError("identifier parameter is required"), nil
				}
				resourceType := opslevel.AliasOwnerTypeEnum(resourceTypeString)
				resp, err := client.GetAliasableResource(resourceType, identifier)
				switch v := resp.(type) {
				case *opslevel.Service:
					lastDeploy, err1 := v.GetLastDeploy(client, nil)
					properties, err2 := v.GetProperties(client, nil)
					v.LastDeploy = lastDeploy
					v.Properties = properties
					return newToolResult(v, errors.Join(err1, err2))
				default:
					return newToolResult(resp, err)
				}
			})

		// Register all documents, filtered by search term
		s.AddTool(
			mcp.NewTool("documents",
				mcp.WithDescription("Get all the documents for the OpsLevel account. Documents are filterable by search term. Documents could be things like runbooks, integration documentation, api documentation, readme's, or other forms of documentation."),
				mcp.WithString("searchTerm", mcp.Description("To filter documents with.")),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Documents in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				searchTerm := req.GetString("searchTerm", "")
				variables := getListDocumentPayloadVariables(searchTerm)
				resp, err := client.ListDocuments(&variables)
				return newToolResult(resp.Nodes, err)
			})

		// Register document by id
		s.AddTool(
			mcp.NewTool("document",
				mcp.WithDescription("Get the contents of a technical or api document in the OpsLevel account, specified by document 'id' or the 'preferredApiDocument' (on a component). Documents could be things like runbooks, integration documentation, api documentation, readme's, or other forms of documentation."),
				mcp.WithString("id", mcp.Required(), mcp.Description("The id of the document to fetch.")),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Document in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id, err := req.RequireString("id")
				if err != nil {
					return mcp.NewToolResultError("id parameter is required"), nil
				}
				resp, err := client.GetDocument(opslevel.ID(id))
				return newToolResult(resp, err)
			})

		// Register all documents, filtered by service id and search term
		s.AddTool(
			mcp.NewTool("documentsOnService",
				mcp.WithDescription("Get all documents on a specified service for the OpsLevel account, specified by service id and filtered by search term. Documents could be things like runbooks, integration documentation, api documentation, readme's, or other forms of documentation."),
				mcp.WithString("serviceId", mcp.Required(), mcp.Description("The id of the service which the documents are on.")),
				mcp.WithString("searchTerm", mcp.Description("To filter documents with.")),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Documents for Service in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				serviceId, err := req.RequireString("serviceId")
				if err != nil {
					return mcp.NewToolResultError("serviceId parameter is required"), nil
				}
				service := opslevel.Service{
					ServiceId: opslevel.ServiceId{
						Id: opslevel.ID(serviceId),
					},
				}
				searchTerm := req.GetString("searchTerm", "")
				variables := getListDocumentPayloadVariables(searchTerm)
				resp, err := service.GetDocuments(client, &variables)
				return newToolResult(resp, err)
			})

		// Register checks
		s.AddTool(
			mcp.NewTool(
				"checks",
				mcp.WithDescription("Get all the checks in the OpsLevel account. Checks provide a foundation for evaluating the maturity of software components, allowing for the definition and enforcement of criteria that ensure components are built and maintained according to best practices. Check priority is determined by level index, not level name—lower index means higher priority."),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Checks in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				resp, err := client.ListChecks(nil)
				if err != nil {
					return mcp.NewToolResultErrorFromErr("failed to list checks", err), nil
				}
				var checks []serializedCheck
				for _, node := range resp.Nodes {
					checks = append(checks, serializedCheck{
						Id:          string(node.Id),
						Name:        node.Name,
						Owner:       node.Owner.Team.Alias,
						Description: node.Description,
						Notes:       node.Notes,
						Type:        string(node.Type),
						Level:       serializedLevel{Alias: node.Level.Alias, Index: node.Level.Index},
						Category:    node.Category.Name,
						Enabled:     node.Enabled,
					})
				}
				return newToolResult(checks, nil)
			})

		s.AddTool(
			mcp.NewTool(
				"componentChecks",
				mcp.WithDescription("Get all the checks for a specific component in the OpsLevel account. Checks are organized by level in a rubric, with each level containing a set of checks that must be passed to achieve that level."),
				mcp.WithString("serviceId", mcp.Required(), mcp.Description("The id of the service to fetch.")),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Rubric of Checks for Component",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				serviceId, err := req.RequireString("serviceId")
				if err != nil {
					return mcp.NewToolResultError("serviceId parameter is required"), nil
				}
				service, err := client.GetService(serviceId)
				if err != nil {
					return mcp.NewToolResultErrorFromErr("failed to get service", err), nil
				}
				if service.Id == "" {
					return mcp.NewToolResultError(fmt.Sprintf("service with id %s not found", serviceId)), nil
				}

				stats, err := service.GetServiceStats(client)
				if err != nil {
					return mcp.NewToolResultErrorFromErr("failed to get service stats", err), nil
				}

				result := serializedCheckResults{
					CurrentLevel: serializedLevel{
						Alias: stats.Rubric.Level.Alias,
						Index: stats.Rubric.Level.Index,
					},
				}
				if stats.Rubric.CheckResults.NextLevel.Level.Alias != "" {
					result.NextLevel = &serializedLevel{
						Alias: stats.Rubric.CheckResults.NextLevel.Level.Alias,
						Index: stats.Rubric.CheckResults.NextLevel.Level.Index,
					}
				}

				for _, checkResultsByLevel := range stats.Rubric.CheckResults.ByLevel.Nodes {
					byLevel := serializedCheckResultsByLevel{
						Level: serializedLevel{
							Alias: checkResultsByLevel.Level.Alias,
							Index: checkResultsByLevel.Level.Index,
						},
					}
					for _, checkResult := range checkResultsByLevel.Items.Nodes {
						byLevel.CheckResults = append(byLevel.CheckResults, serializedCheckResult{
							CheckId:     string(checkResult.Check.Id),
							CheckName:   checkResult.Check.Name,
							Message:     checkResult.Message,
							Status:      string(checkResult.Status),
							LastUpdated: checkResult.LastUpdated,
						})
					}
					result.ByLevel = append(result.ByLevel, byLevel)
				}

				return newToolResult(result, nil)
			})

		// Register campaigns tool
		s.AddTool(
			mcp.NewTool(
				"campaigns",
				mcp.WithDescription("Get all the campaigns in the OpsLevel account. Campaigns are used to track and manage initiatives or projects within OpsLevel."),
				mcp.WithString("status", mcp.Description("Filter campaigns by status, default is 'in_progress'"), mcp.Enum(opslevel.AllCampaignStatusEnum...)),
				mcp.WithToolAnnotation(mcp.ToolAnnotation{
					Title:           "Campaigns in OpsLevel",
					ReadOnlyHint:    &trueValue,
					DestructiveHint: &falseValue,
					IdempotentHint:  &trueValue,
					OpenWorldHint:   &trueValue,
				}),
			),
			func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args := &opslevel.ListCampaignsVariables{}
				status := req.GetString("status", "")
				if status != "" {
					status_enum := opslevel.CampaignStatusEnum(status)
					args.Status = &status_enum
				}

				resp, err := client.ListCampaigns(args)
				if err != nil {
					return mcp.NewToolResultErrorFromErr("failed to list campaigns", err), nil
				}
				var campaigns []serializedCampaign
				for _, node := range resp.Nodes {
					c := serializedCampaign{
						Id:           string(node.Id),
						Name:         node.Name,
						ProjectBrief: node.ProjectBrief,
						Status:       string(node.Status),
						HtmlURL:      node.HtmlUrl,
						CheckStats:   node.CheckStats,
						ServiceStats: node.ServiceStats,
					}
					if node.Owner != (opslevel.TeamId{}) {
						c.Owner = &node.Owner
					}
					if node.StartDate != (iso8601.Time{}) {
						c.StartDate = &node.StartDate
					}
					if node.EndedDate != (iso8601.Time{}) {
						c.EndedDate = &node.EndedDate
					}
					if node.TargetDate != (iso8601.Time{}) {
						c.TargetDate = &node.TargetDate
					}
					if len(node.Reminder.Channels) > 0 {
						c.Reminder = &node.Reminder
					}
					if node.Filter != (opslevel.FilterId{}) {
						c.Filter = &node.Filter
					}
					if node.CheckStats != (opslevel.Stats{}) {
						c.CheckStats = node.CheckStats
					}

					campaigns = append(campaigns, c)
				}

				return newToolResult(campaigns, err)
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

func getListDocumentPayloadVariables(searchTerm string) opslevel.PayloadVariables {
	return opslevel.PayloadVariables{
		"searchTerm": searchTerm,
		"after":      "",
		"first":      100,
	}
}
