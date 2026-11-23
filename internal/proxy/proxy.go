// Package proxy implements the gateway: a reverse proxy that inspects JSON
// request bodies on their way to an LLM API and blocks or redacts the ones
// that carry credentials.
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/roei10101/promptgate/internal/detect"
)

// Mode decides what the gateway does with a request that contains a finding.
type Mode string

const (
	// ModeBlock rejects the request with 403 and never contacts the upstream.
	ModeBlock Mode = "block"
	// ModeRedact replaces each finding with a marker and forwards the rest.
	ModeRedact Mode = "redact"
	// ModeMonitor logs the findings and forwards the request unchanged.
	ModeMonitor Mode = "monitor"
)

// ParseMode converts a command-line value into a Mode.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case ModeBlock, ModeRedact, ModeMonitor:
		return m, nil
	default:
		return "", fmt.Errorf("unknown mode %q (want block, redact or monitor)", s)
	}
}

// DefaultMaxBodyBytes is the largest request body the gateway will buffer.
const DefaultMaxBodyBytes = 10 << 20

// HealthPath is answered by the gateway itself and never forwarded.
const HealthPath = "/healthz"

// ActionHeader is set on responses to requests the gateway acted on.
const ActionHeader = "X-Promptgate-Action"

// Config configures a gateway handler.
type Config struct {
	// Upstream is the base URL of the LLM API, e.g. https://api.example.com.
	Upstream *url.URL
	// Mode defaults to ModeBlock.
	Mode Mode
	// Detectors defaults to detect.Secrets().
	Detectors []detect.Detector
	// MaxBodyBytes defaults to DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

type gateway struct {
	cfg   Config
	proxy *httputil.ReverseProxy
}

// New returns the gateway's HTTP handler.
func New(cfg Config) (http.Handler, error) {
	if cfg.Upstream == nil || cfg.Upstream.Host == "" {
		return nil, errors.New("upstream URL with a host is required")
	}
	if cfg.Upstream.Scheme != "http" && cfg.Upstream.Scheme != "https" {
		return nil, fmt.Errorf("upstream scheme must be http or https, got %q", cfg.Upstream.Scheme)
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeBlock
	}
	if _, err := ParseMode(string(cfg.Mode)); err != nil {
		return nil, err
	}
	if cfg.Detectors == nil {
		cfg.Detectors = detect.Secrets()
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	g := &gateway{cfg: cfg}
	g.proxy = &httputil.ReverseProxy{
		// Rewrite (rather than Director) drops client-supplied forwarding
		// headers and does not add X-Forwarded-For, so the client's address
		// is not disclosed to a third-party API.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.Upstream)
		},
		// Flush every write so streamed (server-sent event) completions
		// reach the client token by token.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			cfg.Logger.Error("upstream request failed", "method", r.Method, "path", r.URL.Path, "error", err.Error())
			writeError(w, http.StatusBadGateway, "promptgate_upstream_error", "the upstream API could not be reached", nil)
		},
	}
	return g, nil
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == HealthPath {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`+"\n")
		return
	}

	if r.Body != nil && r.Body != http.NoBody && isJSON(r.Header.Get("Content-Type")) {
		if done := g.inspect(w, r); done {
			return
		}
	}
	g.proxy.ServeHTTP(w, r)
}

// inspect buffers and scans a JSON request body, applying the configured
// mode. It reports true when it has already written the response.
func (g *gateway) inspect(w http.ResponseWriter, r *http.Request) (done bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "promptgate_body_too_large",
				fmt.Sprintf("request body exceeds the %d byte limit", g.cfg.MaxBodyBytes), nil)
			return true
		}
		writeError(w, http.StatusBadRequest, "promptgate_bad_request", "could not read the request body", nil)
		return true
	}

	violations, redacted, ok := inspectJSON(body, g.cfg.Detectors)
	if ok && len(violations) > 0 {
		sortViolations(violations)
		g.cfg.Logger.Warn("sensitive data in request",
			"action", string(g.cfg.Mode), "method", r.Method, "path", r.URL.Path,
			"detectors", detectorNames(violations), "findings", len(violations))

		switch g.cfg.Mode {
		case ModeBlock:
			w.Header().Set(ActionHeader, "blocked")
			writeError(w, http.StatusForbidden, "promptgate_blocked",
				"request blocked: it contains "+strings.Join(detectorNames(violations), ", "), violations)
			return true
		case ModeRedact:
			body = redacted
			w.Header().Set(ActionHeader, "redacted")
		case ModeMonitor:
			w.Header().Set(ActionHeader, "monitored")
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return false
}

// isJSON reports whether a Content-Type names a JSON media type.
func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// sortViolations orders violations by path, then detector. JSON objects are
// walked in random order, so this keeps logs and responses deterministic.
func sortViolations(v []Violation) {
	sort.SliceStable(v, func(i, j int) bool {
		if v[i].Path != v[j].Path {
			return v[i].Path < v[j].Path
		}
		return v[i].Detector < v[j].Detector
	})
}

// detectorNames returns the distinct detector names in v, sorted.
func detectorNames(v []Violation) []string {
	seen := make(map[string]bool, len(v))
	var names []string
	for _, x := range v {
		if !seen[x.Detector] {
			seen[x.Detector] = true
			names = append(names, x.Detector)
		}
	}
	sort.Strings(names)
	return names
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Type     string      `json:"type"`
	Message  string      `json:"message"`
	Findings []Violation `json:"findings,omitempty"`
}

// writeError writes an error in the {"error": {...}} envelope that LLM API
// clients already know how to surface.
func writeError(w http.ResponseWriter, status int, kind, message string, findings []Violation) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errorDetail{Type: kind, Message: message, Findings: findings}})
}
