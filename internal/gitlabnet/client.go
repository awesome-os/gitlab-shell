// Package gitlabnet provides client utilities for interacting with GitLab's internal API.
package gitlabnet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"gitlab.com/gitlab-org/gitlab-shell/v14/client"
	"gitlab.com/gitlab-org/labkit/v2/log"

	"gitlab.com/gitlab-org/gitlab-shell/v14/internal/config"
)

// GetClient creates and returns a new GitlabNetClient configured with the provided settings.
func GetClient(config *config.Config) (*client.GitlabNetClient, error) {
	httpClient, err := config.HTTPClient()
	if err != nil {
		return nil, err
	}

	if httpClient == nil {
		return nil, fmt.Errorf("unsupported protocol")
	}

	return client.NewGitlabNetClient(config.HTTPSettings.User, config.HTTPSettings.Password, config.Secret, httpClient)
}

// ParseJSON decodes JSON from an HTTP response into the provided response interface.
//
// When decoding fails, the details needed to diagnose the failure — the
// request URL, the status code, the content type and the decoding error —
// are written to the log, so that a non-JSON response from the internal
// API can be diagnosed from the gitlab-shell logs alone. The returned
// error stays generic on purpose: several commands print it to the SSH
// client's stderr, so it must not carry internal API details. See
// https://gitlab.com/gitlab-org/gitlab-shell/-/issues/888
func ParseJSON(hr *http.Response, response interface{}) error {
	if err := json.NewDecoder(hr.Body).Decode(response); err != nil {
		logFailedParse(hr, err)

		return fmt.Errorf("parsing failed")
	}

	return nil
}

// logFailedParse records a JSON decoding failure, together with the
// request that produced the response, in the server-side log.
func logFailedParse(hr *http.Response, err error) {
	ctx := context.Background()
	if hr.Request != nil {
		ctx = hr.Request.Context()
	}

	logger := parseLogger(ctx)
	logger.ErrorContext(ctx, "Failed to parse internal API response",
		log.HTTPURL(requestURL(hr)),
		log.HTTPStatusCode(hr.StatusCode),
		log.ContentType(hr.Header.Get("Content-Type")),
		log.ErrorMessage(err.Error()),
	)
}

// parseLogger returns the logger attached to ctx, or the default logger
// when the request carries no context at all.
//
// log.FromContext cannot be trusted with a context-less request: its
// fallback is a fresh logger writing to os.Stderr, not slog.Default().
// The lfstransfer client builds its requests with retryablehttp, which
// attaches no context, so on that path the record would be printed to
// the SSH client's stderr — the URL and decode error included — instead
// of reaching gitlab-shell.log, which internal/logger.ConfigureLogger
// points slog.Default() at. Requests that do carry a context keep the
// request logger, including its correlation ID.
func parseLogger(ctx context.Context) *slog.Logger {
	if ctx == context.Background() {
		return slog.Default()
	}

	return log.FromContext(ctx)
}

// requestURL returns the URL of the request that produced hr, or a
// placeholder for responses that were not created by an HTTP client.
//
// Only scheme, host and path are included: the LabKit definition of the
// http_url field requires query strings and fragments to be omitted, and
// several internal-API callers carry data in the query (keys, user
// identifiers, usernames) that must not reach the log.
func requestURL(hr *http.Response) string {
	if hr.Request != nil && hr.Request.URL != nil {
		u := *hr.Request.URL
		u.RawQuery = ""
		u.Fragment = ""
		u.User = nil
		return u.String()
	}

	return "unknown URL"
}

// GlID represents a parsed GitLab gl_id identifier.
// Use UserID() or DeployTokenID() to extract the typed value.
type GlID struct {
	userID        int
	deployTokenID int
}

// UserID returns the numeric user ID and true if the gl_id represents a user.
func (g *GlID) UserID() (int, bool) {
	return g.userID, g.userID != 0
}

// DeployTokenID returns the numeric deploy token ID and true if the gl_id
// represents a deploy token.
func (g *GlID) DeployTokenID() (int, bool) {
	return g.deployTokenID, g.deployTokenID != 0
}

// ParseGlID parses a GitLab gl_id string into its typed representation.
//
// Known gl_id formats (see https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/gl_id.rb):
//   - "user-<N>"         → UserID() returns (N, true)
//   - "deploy-token-<N>" → DeployTokenID() returns (N, true)
//
// Returns an error for unrecognized or malformed formats.
func ParseGlID(glID string) (*GlID, error) {
	switch {
	case strings.HasPrefix(glID, "user-"):
		id, err := strconv.Atoi(glID[len("user-"):])
		if err != nil {
			return nil, fmt.Errorf("invalid user gl_id %q: %w", glID, err)
		}
		return &GlID{userID: id}, nil
	case strings.HasPrefix(glID, "deploy-token-"):
		id, err := strconv.Atoi(glID[len("deploy-token-"):])
		if err != nil {
			return nil, fmt.Errorf("invalid deploy-token gl_id %q: %w", glID, err)
		}
		return &GlID{deployTokenID: id}, nil
	default:
		return nil, fmt.Errorf("unknown gl_id format %q", glID)
	}
}

// ParseIP extracts and returns the IP address from a remote address string.
// It handles both plain IP addresses and host:port combinations.
func ParseIP(remoteAddr string) string {
	// The remoteAddr field can be filled by:
	// 1. An IP address via the SSH_CONNECTION environment variable
	// 2. A host:port combination via the PROXY protocol
	ip, _, err := net.SplitHostPort(remoteAddr)

	// If we don't have a port or can't parse this address for some reason,
	// just return the original string.
	if err != nil {
		return remoteAddr
	}

	return ip
}
