package main

import (
	"io"
	"strings"
	"testing"

	"github.com/roei10101/promptgate/internal/proxy"
)

func env(pairs map[string]string) func(string) string {
	return func(key string) string { return pairs[key] }
}

func TestParseOptionsDefaults(t *testing.T) {
	opts, err := parseOptions([]string{"-upstream", "https://api.example"}, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if opts.listen != "127.0.0.1:8080" {
		t.Errorf("listen = %q, want loopback by default", opts.listen)
	}
	if opts.mode != proxy.ModeBlock {
		t.Errorf("mode = %q, want block by default", opts.mode)
	}
	if opts.maxBodyBytes != proxy.DefaultMaxBodyBytes {
		t.Errorf("maxBodyBytes = %d", opts.maxBodyBytes)
	}
	if opts.upstream.String() != "https://api.example" {
		t.Errorf("upstream = %s", opts.upstream)
	}
}

func TestParseOptionsEnvironmentAndFlagPrecedence(t *testing.T) {
	environment := env(map[string]string{
		"PROMPTGATE_UPSTREAM":       "http://localhost:11434",
		"PROMPTGATE_MODE":           "redact",
		"PROMPTGATE_LISTEN":         ":9000",
		"PROMPTGATE_MAX_BODY_BYTES": "2048",
	})

	opts, err := parseOptions(nil, environment, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if opts.upstream.Host != "localhost:11434" || opts.mode != proxy.ModeRedact ||
		opts.listen != ":9000" || opts.maxBodyBytes != 2048 {
		t.Errorf("environment not applied: %+v", opts)
	}

	opts, err = parseOptions([]string{"-mode", "monitor"}, environment, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if opts.mode != proxy.ModeMonitor {
		t.Errorf("mode = %q, want the flag to override the environment", opts.mode)
	}
}

func TestParseOptionsRejectsBadInput(t *testing.T) {
	cases := map[string][]string{
		"an upstream is required": {},
		"invalid upstream URL":    {"-upstream", "api.example"},
		"unknown mode":            {"-upstream", "https://api.example", "-mode", "shrug"},
		"invalid max-body-bytes":  {"-upstream", "https://api.example", "-max-body-bytes", "-1"},
		"unexpected argument":     {"-upstream", "https://api.example", "serve"},
	}
	for want, args := range cases {
		_, err := parseOptions(args, env(nil), io.Discard)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("args %v: error = %v, want one containing %q", args, err, want)
		}
	}
}

func TestVersionDoesNotNeedAnUpstream(t *testing.T) {
	var out strings.Builder
	if err := run(t.Context(), []string{"-version"}, env(nil), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "promptgate "+version) {
		t.Errorf("output = %q", out.String())
	}
}
