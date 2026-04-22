package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/opslevel/opslevel-go/v2025"
	"github.com/spf13/viper"
)

type contextKey int

const graphClientContextKey contextKey = iota

// oauthContextFunc returns an HTTPContextFunc that extracts the Bearer token
// from the Authorization header and injects a per-request GraphQL client into
// the context. Tools call clientFromCtx to pick it up; if absent they fall
// back to the startup-configured client (stdio mode).
func oauthContextFunc(version string) server.HTTPContextFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		token := bearerToken(r)
		if token == "" {
			return ctx
		}
		return context.WithValue(ctx, graphClientContextKey, newOAuthClient(version, token))
	}
}

// clientFromCtx returns the per-request GraphQL client injected by
// oauthContextFunc, falling back to fallback when not present (stdio mode).
func clientFromCtx(ctx context.Context, fallback *opslevel.Client) *opslevel.Client {
	if c, ok := ctx.Value(graphClientContextKey).(*opslevel.Client); ok {
		return c
	}
	return fallback
}

// newOAuthClient builds a GraphQL client for the given OAuth Bearer token.
// Unlike NewGraphClient it skips Validate() — the token is validated implicitly
// by the monolith's GraphQL controller on the first call.
func newOAuthClient(version, token string) *opslevel.Client {
	timeout := time.Second * time.Duration(viper.GetInt("api-timeout"))
	return opslevel.NewGQLClient(
		opslevel.SetAPIToken(token),
		opslevel.SetURL(viper.GetString("api-url")),
		opslevel.SetTimeout(timeout),
		opslevel.SetUserAgentExtra(fmt.Sprintf("mcp-%s", version)),
	)
}

// requireBearerToken is HTTP middleware that rejects requests without an
// Authorization: Bearer <token> header with 401 Unauthorized.
// Requests to /.well-known/* are always allowed through.
func requireBearerToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			next.ServeHTTP(w, r)
			return
		}
		if bearerToken(r) == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp.opslevel.com"`)
			http.Error(w, `{"error":"unauthorized","error_description":"Bearer token required"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	return ""
}
