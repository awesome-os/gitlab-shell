package gitlabnet

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/require"
	"gitlab.com/gitlab-org/labkit/v2/log"
)

type capturedLogRecord struct {
	Level   slog.Level
	Message string
	Values  []string
}

type capturingLogHandler struct {
	mu      *sync.Mutex
	records *[]capturedLogRecord
}

func newCapturingLogHandler() (*capturingLogHandler, *[]capturedLogRecord) {
	records := &[]capturedLogRecord{}
	return &capturingLogHandler{mu: &sync.Mutex{}, records: records}, records
}

func (h *capturingLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *capturingLogHandler) Handle(_ context.Context, record slog.Record) error {
	values := []string{}
	record.Attrs(func(attr slog.Attr) bool {
		values = append(values, attr.Value.String())
		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = append(*h.records, capturedLogRecord{Level: record.Level, Message: record.Message, Values: values})
	return nil
}

func (h *capturingLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h *capturingLogHandler) WithGroup(_ string) slog.Handler { return h }

// TestParseJSONErrorStaysGenericAndLogsContext is the regression test for
// https://gitlab.com/gitlab-org/gitlab-shell/-/issues/888 : when the
// internal API returns a non-JSON body, the failure must be diagnosable
// from the gitlab-shell logs (request URL, status and content type are
// logged), while the error returned to callers — and printed to the SSH
// client — stays exactly "parsing failed".
func TestParseJSONErrorStaysGenericAndLogsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>not json</body></html>"))
	}))
	defer server.Close()

	// The query string and fragment carry data that must not reach the
	// log (keys, user identifiers, usernames), so the logged URL must
	// contain only scheme, host and path.
	url := server.URL + "/api/v4/internal/lfs_authenticate?key=secret-key&user_identifier=42#section"

	resp, err := http.Get(url) //nolint:bodyclose // body is closed below
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	handler, records := newCapturingLogHandler()
	ctx := log.WithLogger(context.Background(), slog.New(handler))
	resp.Request = resp.Request.WithContext(ctx)

	var dst struct {
		Message string `json:"message"`
	}
	err = ParseJSON(resp, &dst)
	require.EqualError(t, err, "parsing failed")

	require.Len(t, *records, 1)
	record := (*records)[0]
	require.Equal(t, slog.LevelError, record.Level)
	require.Equal(t, "Failed to parse internal API response", record.Message)
	loggedURL := server.URL + "/api/v4/internal/lfs_authenticate"
	require.Contains(t, record.Values, loggedURL)
	// NotContains on the []string compares whole elements, so a leaked
	// query value would never equal "secret-key" exactly — join the
	// values first so the checks below are real substring checks.
	loggedValues := strings.Join(record.Values, " ")
	require.NotContains(t, loggedValues, "secret-key")
	require.NotContains(t, loggedValues, "user_identifier")
	require.NotContains(t, loggedValues, "section")
	require.Contains(t, record.Values, "200")
	require.Contains(t, record.Values, "text/html")
}

// TestParseJSONWithoutContextLoggerUsesDefaultLogger covers callers whose
// requests carry no context at all: the lfstransfer client builds its
// requests with retryablehttp.NewRequest, which attaches no context, so
// the request has no logger in it. The parse-failure record must then go
// to the default logger (the one internal/logger.ConfigureLogger points
// at gitlab-shell.log), never to os.Stderr: in OpenSSH mode stderr is
// the SSH client's stderr, and the record carries the request URL and
// the decode error.
func TestParseJSONWithoutContextLoggerUsesDefaultLogger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>not json</body></html>"))
	}))
	defer server.Close()

	// Capture os.Stderr for the duration of the call.
	origStderr := os.Stderr
	stderrR, stderrW, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = stderrW
	defer func() { os.Stderr = origStderr }()

	// Stand in for the configured default logger with a capturing one.
	handler, records := newCapturingLogHandler()
	origDefault := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(origDefault)

	// Build the request exactly the way the lfstransfer client does:
	// retryablehttp.NewRequest attaches no context.
	url := server.URL + "/api/v4/internal/lfs/objects/batch?key=secret-key"
	req, err := retryablehttp.NewRequest(http.MethodPost, url, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req.Request)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var dst struct {
		Message string `json:"message"`
	}
	err = ParseJSON(resp, &dst)
	require.EqualError(t, err, "parsing failed")

	require.NoError(t, stderrW.Close())
	stderrBytes, err := io.ReadAll(stderrR)
	require.NoError(t, err)
	require.NotContains(t, string(stderrBytes), "Failed to parse internal API response")

	require.Len(t, *records, 1)
	record := (*records)[0]
	require.Equal(t, slog.LevelError, record.Level)
	require.Equal(t, "Failed to parse internal API response", record.Message)
	require.Contains(t, record.Values, server.URL+"/api/v4/internal/lfs/objects/batch")
	require.NotContains(t, strings.Join(record.Values, " "), "secret-key")
	require.Contains(t, record.Values, "200")
	require.Contains(t, record.Values, "text/html")
}

func TestParseGlID(t *testing.T) {
	tests := []struct {
		desc              string
		input             string
		wantUserID        int
		wantIsUser        bool
		wantDeployTokenID int
		wantIsDeployToken bool
		wantErr           bool
	}{
		{desc: "user-1", input: "user-1", wantUserID: 1, wantIsUser: true},
		{desc: "user-42", input: "user-42", wantUserID: 42, wantIsUser: true},
		{desc: "deploy-token-52", input: "deploy-token-52", wantDeployTokenID: 52, wantIsDeployToken: true},
		{desc: "deploy-token-1", input: "deploy-token-1", wantDeployTokenID: 1, wantIsDeployToken: true},
		{desc: "user- without number", input: "user-", wantErr: true},
		{desc: "user-abc", input: "user-abc", wantErr: true},
		{desc: "deploy-token- without number", input: "deploy-token-", wantErr: true},
		{desc: "deploy-token-abc", input: "deploy-token-abc", wantErr: true},
		{desc: "key-1 unknown prefix", input: "key-1", wantErr: true},
		{desc: "empty string", input: "", wantErr: true},
		{desc: "plain numeric", input: "1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := ParseGlID(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)

			userID, isUser := got.UserID()
			require.Equal(t, tt.wantUserID, userID)
			require.Equal(t, tt.wantIsUser, isUser)

			deployTokenID, isDeployToken := got.DeployTokenID()
			require.Equal(t, tt.wantDeployTokenID, deployTokenID)
			require.Equal(t, tt.wantIsDeployToken, isDeployToken)
		})
	}
}
