package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/opslevel/opslevel-go/v2025"
	"github.com/rs/zerolog/log"
)

var (
	DD_AGENT_HOST = "DD_AGENT_HOST"
	DD_API_KEY    = "DD_API_KEY"
	DD_APP_KEY    = "DD_APP_KEY"
	DD_SITE       = "DD_SITE"
)

type Telemetry struct {
	client   *opslevel.Client
	dd       *statsd.Client
	mu       sync.Mutex
	account  *opslevel.Account
	hostname string
}

func NewTelemetry(client *opslevel.Client) (*Telemetry, error) {
	telemetry := &Telemetry{
		client: client,
	}

	err := telemetry.initDatadog()
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	telemetry.hostname = hostname

	return telemetry, nil
}

func (t *Telemetry) Track(toolName string, args map[string]any) {
	go func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		if t.dd == nil {
			return
		}

		if t.account == nil {
			err := t.fetchAccountDetails()
			if err != nil {
				log.Warn().Err(err).Msg("failed to fetch account details for telemetry")
			}
		}

		tags := t.getTags(toolName)
		text := t.getEventText(args)

		event := &statsd.Event{
			Title:      "MCP Tool Executed",
			Text:       text,
			Timestamp:  time.Now(),
			Hostname:   t.hostname,
			SourceTypeName: "opslevel-mcp",
			Tags:       tags,
		}

		err := t.dd.Event(event)
		if err != nil {
			log.Warn().Err(err).Msg("failed to send telemetry event to Datadog")
		}
	}()
}

func (t *Telemetry) initDatadog() error {
	// Check for Datadog credentials
	if os.Getenv(DD_API_KEY) == "" || os.Getenv(DD_APP_KEY) == "" {
		log.Info().Msg("Datadog API or APP key not set, telemetry disabled")
		return nil
	}

	// Initialize Datadog client
	dd, err := statsd.New("")
	if err != nil {
		return fmt.Errorf("failed to create datadog client: %w", err)
	}
	t.dd = dd
	return nil
}

func (t *Telemetry) fetchAccountDetails() error {
	var q struct {
		Account opslevel.Account `json:"account"`
	}
	err := t.client.Query(&q, nil)
	if err != nil {
		return fmt.Errorf("failed to get account details: %w", err)
	}
	t.account = &q.Account
	return nil
}

func (t *Telemetry) getTags(toolName string) []string {
	tags := []string{
		fmt.Sprintf("tool:%s", toolName),
	}
	if t.account != nil {
		tags = append(tags,
			fmt.Sprintf("account_id:%s", t.account.Id),
			fmt.Sprintf("account_name:%s", t.account.Name),
		)
	}
	return tags
}

func (t *Telemetry) getEventText(args map[string]any) string {
	var text string
	if len(args) > 0 {
		argsJSON, err := json.Marshal(args)
		if err != nil {
			log.Warn().Err(err).Msg("failed to marshal tool args for telemetry")
			text = fmt.Sprintf("Tool executed with args: %v", args)
		} else {
			text = fmt.Sprintf("Tool executed with args:\n```json\n%s\n```", string(argsJSON))
		}
	} else {
		text = "Tool executed with no arguments"
	}
	return text
}
