package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Fake credentials are assembled at run time; see internal/detect tests.
var (
	fakeAWS    = "AKIA" + strings.Repeat("Q", 16)
	fakeGitHub = "ghp_" + strings.Repeat("a1B2", 9)
)

// upstream is a fake LLM API that records what it receives.
type upstream struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recorded
}

type recorded struct {
	Method, Path, Query, Host string
	Header                    http.Header
	Body                      string
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.requests = append(u.requests, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Clone(), string(body)})
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "yes")
		_, _ = io.WriteString(w, `{"reply":"ok"}`)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) seen() []recorded {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]recorded(nil), u.requests...)
}

// newGateway starts a gateway in front of up and returns its base URL and
// a buffer holding its log output.
func newGateway(t *testing.T, up *upstream, mode Mode, maxBody int64) (string, *bytes.Buffer) {
	t.Helper()
	target, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	h, err := New(Config{
		Upstream:     target,
		Mode:         mode,
		MaxBodyBytes: maxBody,
		Logger:       slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, &logs
}

func post(t *testing.T, url, contentType, body string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Post(url, contentType, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

func chatBody(content string) string {
	b, _ := json.Marshal(map[string]any{
		"model":       "test-model",
		"temperature": 0.2,
		"max_tokens":  json.Number("12345678901234567890"), // larger than float64 can hold exactly
		"messages": []map[string]string{
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": content},
		},
	})
	return string(b)
}

func TestCleanRequestIsForwardedByteForByte(t *testing.T) {
	up := newUpstream(t)
	gw, _ := newGateway(t, up, ModeBlock, 0)
	body := `{ "messages": [ {"role":"user","content":"hello <b>world</b>"} ],  "n": 1.50 }`

	req, _ := http.NewRequest(http.MethodPost, gw+"/v1/chat/completions?stream=false", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer client-credential")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || string(respBody) != `{"reply":"ok"}` {
		t.Fatalf("got %d %q, want the upstream response", resp.StatusCode, respBody)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Error("upstream response headers were not passed through")
	}
	if got := resp.Header.Get(ActionHeader); got != "" {
		t.Errorf("%s = %q on a clean request, want it unset", ActionHeader, got)
	}

	seen := up.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(seen))
	}
	got := seen[0]
	if got.Body != body {
		t.Errorf("upstream body = %q, want it unchanged %q", got.Body, body)
	}
	if got.Path != "/v1/chat/completions" || got.Query != "stream=false" {
		t.Errorf("upstream got %s?%s", got.Path, got.Query)
	}
	if got.Header.Get("Authorization") != "Bearer client-credential" {
		t.Error("the client's Authorization header was not forwarded")
	}
	if want := strings.TrimPrefix(up.URL, "http://"); got.Host != want {
		t.Errorf("upstream Host = %q, want %q", got.Host, want)
	}
	if got.Header.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For must not be sent to the upstream")
	}
}

func TestBlockModeRejectsWithoutContactingUpstream(t *testing.T) {
	up := newUpstream(t)
	gw, logs := newGateway(t, up, ModeBlock, 0)

	resp, body := post(t, gw+"/v1/chat/completions", "application/json",
		chatBody("why does this fail? key="+fakeAWS+" token="+fakeGitHub))

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get(ActionHeader); got != "blocked" {
		t.Errorf("%s = %q, want blocked", ActionHeader, got)
	}
	if n := len(up.seen()); n != 0 {
		t.Fatalf("upstream saw %d requests, want 0", n)
	}

	var parsed errorBody
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, body)
	}
	if parsed.Error.Type != "promptgate_blocked" {
		t.Errorf("error type = %q", parsed.Error.Type)
	}
	want := []Violation{
		{Detector: "aws_access_key_id", Path: "messages[1].content"},
		{Detector: "github_token", Path: "messages[1].content"},
	}
	if len(parsed.Error.Findings) != len(want) {
		t.Fatalf("findings = %+v, want %+v", parsed.Error.Findings, want)
	}
	for i := range want {
		if parsed.Error.Findings[i] != want[i] {
			t.Errorf("finding %d = %+v, want %+v", i, parsed.Error.Findings[i], want[i])
		}
	}

	// The secret must never be echoed back or written to the log.
	for name, text := range map[string]string{"response": body, "log": logs.String()} {
		if strings.Contains(text, fakeAWS) || strings.Contains(text, fakeGitHub) {
			t.Errorf("%s leaks the secret: %s", name, text)
		}
	}
	if !strings.Contains(logs.String(), "aws_access_key_id") {
		t.Errorf("log does not name the detector: %s", logs.String())
	}
}

func TestRedactModeForwardsRedactedBody(t *testing.T) {
	up := newUpstream(t)
	gw, _ := newGateway(t, up, ModeRedact, 0)

	resp, _ := post(t, gw+"/v1/chat/completions", "application/json",
		chatBody("deploy with "+fakeAWS+" <now> & fast"))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get(ActionHeader); got != "redacted" {
		t.Errorf("%s = %q, want redacted", ActionHeader, got)
	}
	seen := up.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(seen))
	}
	sent := seen[0].Body
	if strings.Contains(sent, fakeAWS) {
		t.Fatalf("the secret reached the upstream: %s", sent)
	}

	var doc struct {
		Model     string      `json:"model"`
		MaxTokens json.Number `json:"max_tokens"`
		Messages  []struct{ Role, Content string }
	}
	if err := json.Unmarshal([]byte(sent), &doc); err != nil {
		t.Fatalf("redacted body is not valid JSON: %v\n%s", err, sent)
	}
	if got, want := doc.Messages[1].Content, "deploy with [REDACTED:aws_access_key_id] <now> & fast"; got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
	if doc.Messages[0].Content != "You are helpful." || doc.Model != "test-model" {
		t.Errorf("unrelated fields changed: %s", sent)
	}
	if doc.MaxTokens.String() != "12345678901234567890" {
		t.Errorf("a number was altered by re-encoding: %s", doc.MaxTokens)
	}
	if !strings.Contains(sent, `"temperature":0.2`) {
		t.Errorf("a float was altered by re-encoding: %s", sent)
	}
	if got := seen[0].Header.Get("Content-Length"); got != strconv.Itoa(len(sent)) {
		t.Errorf("Content-Length = %s, body is %d bytes", got, len(sent))
	}
}

func TestMonitorModeForwardsUnchangedAndLogs(t *testing.T) {
	up := newUpstream(t)
	gw, logs := newGateway(t, up, ModeMonitor, 0)
	body := chatBody("token " + fakeGitHub)

	resp, _ := post(t, gw+"/v1/chat/completions", "application/json", body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get(ActionHeader); got != "monitored" {
		t.Errorf("%s = %q, want monitored", ActionHeader, got)
	}
	if seen := up.seen(); len(seen) != 1 || seen[0].Body != body {
		t.Fatalf("upstream did not receive the original body: %+v", seen)
	}
	if !strings.Contains(logs.String(), "github_token") || strings.Contains(logs.String(), fakeGitHub) {
		t.Errorf("log must name the detector and not the secret: %s", logs.String())
	}
}

func TestSecretsInNestedValuesAreFound(t *testing.T) {
	up := newUpstream(t)
	gw, _ := newGateway(t, up, ModeBlock, 0)
	body := `{"messages":[{"role":"user","content":[{"type":"text","text":"see ` + fakeAWS + `"}]}],` +
		`"tools":[{"function":{"description":"uses ` + fakeGitHub + `"}}]}`

	resp, respBody := post(t, gw+"/v1/chat/completions", "application/vnd.api+json", body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	for _, path := range []string{"messages[0].content[0].text", "tools[0].function.description"} {
		if !strings.Contains(respBody, path) {
			t.Errorf("response does not report path %q: %s", path, respBody)
		}
	}
}

func TestBodiesThatAreNotInspectedAreForwarded(t *testing.T) {
	cases := []struct{ name, contentType, body string }{
		{"non-JSON content type", "text/plain", "key " + fakeAWS},
		{"malformed JSON", "application/json", `{"content": "` + fakeAWS},
		{"two JSON documents", "application/json", `{"a":"` + fakeAWS + `"} {"b":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newUpstream(t)
			gw, _ := newGateway(t, up, ModeBlock, 0)
			resp, _ := post(t, gw+"/v1/anything", tc.contentType, tc.body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if seen := up.seen(); len(seen) != 1 || seen[0].Body != tc.body {
				t.Fatalf("upstream did not receive the original body: %+v", seen)
			}
		})
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	up := newUpstream(t)
	gw, _ := newGateway(t, up, ModeBlock, 64)

	resp, body := post(t, gw+"/v1/chat/completions", "application/json",
		`{"content":"`+strings.Repeat("a", 200)+`"}`)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if !strings.Contains(body, "promptgate_body_too_large") {
		t.Errorf("unexpected body: %s", body)
	}
	if n := len(up.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

func TestGetRequestsAreProxied(t *testing.T) {
	up := newUpstream(t)
	gw, _ := newGateway(t, up, ModeBlock, 0)
	resp, err := http.Get(gw + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen := up.seen(); resp.StatusCode != http.StatusOK || len(seen) != 1 || seen[0].Path != "/v1/models" {
		t.Fatalf("status %d, upstream saw %+v", resp.StatusCode, seen)
	}
}

func TestHealthIsAnsweredLocally(t *testing.T) {
	up := newUpstream(t)
	gw, _ := newGateway(t, up, ModeBlock, 0)
	resp, err := http.Get(gw + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if n := len(up.seen()); n != 0 {
		t.Errorf("health check was forwarded to the upstream")
	}
}

func TestUnreachableUpstreamReturnsBadGateway(t *testing.T) {
	up := newUpstream(t)
	gw, _ := newGateway(t, up, ModeBlock, 0)
	up.Close()

	resp, body := post(t, gw+"/v1/chat/completions", "application/json", chatBody("hi"))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(body, "promptgate_upstream_error") {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestUpstreamBasePathIsPrepended(t *testing.T) {
	up := newUpstream(t)
	target, _ := url.Parse(up.URL + "/openai")
	h, err := New(Config{Upstream: target, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen := up.seen(); len(seen) != 1 || seen[0].Path != "/openai/v1/models" {
		t.Fatalf("upstream saw %+v, want path /openai/v1/models", seen)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	mustParse := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	bad := map[string]Config{
		"no upstream":  {},
		"no host":      {Upstream: mustParse("/just/a/path")},
		"bad scheme":   {Upstream: mustParse("ftp://api.example")},
		"unknown mode": {Upstream: mustParse("https://api.example"), Mode: "shrug"},
	}
	for name, cfg := range bad {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New succeeded, want an error", name)
		}
	}
	if _, err := New(Config{Upstream: mustParse("https://api.example")}); err != nil {
		t.Errorf("minimal config rejected: %v", err)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"block": ModeBlock, " Redact ": ModeRedact, "MONITOR": ModeMonitor} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseMode("off"); err == nil {
		t.Error(`ParseMode("off") succeeded, want an error`)
	}
}
