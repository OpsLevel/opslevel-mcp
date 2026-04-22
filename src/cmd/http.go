package cmd

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// oauthServerMetadata is returned from /.well-known/oauth-authorization-server.
// It points MCP clients at the monolith's Doorkeeper OAuth server so they can
// initiate the authorization_code flow automatically.
type oauthServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// wellKnownHandler serves /.well-known/oauth-authorization-server.
func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	apiURL := strings.TrimRight(viper.GetString("api-url"), "/")
	meta := oauthServerMetadata{
		Issuer:                        apiURL,
		AuthorizationEndpoint:         apiURL + "/oauth/authorize",
		TokenEndpoint:                 apiURL + "/oauth/token",
		ResponseTypesSupported:        []string{"code"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meta); err != nil {
		log.Error().Err(err).Msg("failed to encode OAuth server metadata")
	}
}

// startHTTPServer starts the Streamable HTTP MCP server.
// addr is a standard Go listen address like ":8080".
func startHTTPServer(s *server.MCPServer, version, addr string) error {
	httpMCP := server.NewStreamableHTTPServer(s,
		server.WithHTTPContextFunc(oauthContextFunc(version)),
		server.WithStateLess(true),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", wellKnownHandler)
	mux.Handle("/mcp", requireBearerToken(httpMCP))

	log.Info().Str("addr", addr).Msg("Starting MCP HTTP server")
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	return srv.ListenAndServe()
}
