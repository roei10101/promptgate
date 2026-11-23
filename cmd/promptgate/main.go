// Command promptgate runs the gateway: a reverse proxy that sits between
// applications and an LLM API and stops credentials from leaving in prompts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/roei10101/promptgate/internal/proxy"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "promptgate:", err)
		os.Exit(1)
	}
}

// options is the validated command-line configuration.
type options struct {
	listen       string
	upstream     *url.URL
	mode         proxy.Mode
	maxBodyBytes int64
	showVersion  bool
}

// parseOptions reads flags, falling back to PROMPTGATE_* environment
// variables and then to the built-in defaults.
func parseOptions(args []string, getenv func(string) string, stderr io.Writer) (options, error) {
	env := func(key, fallback string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return fallback
	}

	fs := flag.NewFlagSet("promptgate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", env("PROMPTGATE_LISTEN", "127.0.0.1:8080"),
		"address to listen on (env PROMPTGATE_LISTEN)")
	upstream := fs.String("upstream", env("PROMPTGATE_UPSTREAM", ""),
		"base URL of the LLM API to forward to, required (env PROMPTGATE_UPSTREAM)")
	mode := fs.String("mode", env("PROMPTGATE_MODE", string(proxy.ModeBlock)),
		"what to do with a request that contains a secret: block, redact or monitor (env PROMPTGATE_MODE)")
	maxBody := fs.String("max-body-bytes", env("PROMPTGATE_MAX_BODY_BYTES", strconv.Itoa(proxy.DefaultMaxBodyBytes)),
		"largest request body to accept, in bytes (env PROMPTGATE_MAX_BODY_BYTES)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	opts := options{listen: *listen, showVersion: *showVersion}
	if opts.showVersion {
		return opts, nil
	}

	if *upstream == "" {
		return options{}, errors.New("an upstream is required: pass -upstream or set PROMPTGATE_UPSTREAM")
	}
	u, err := url.Parse(*upstream)
	if err != nil {
		return options{}, fmt.Errorf("invalid upstream URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return options{}, fmt.Errorf("invalid upstream URL %q: want http(s)://host[:port][/path]", *upstream)
	}
	opts.upstream = u

	if opts.mode, err = proxy.ParseMode(*mode); err != nil {
		return options{}, err
	}
	opts.maxBodyBytes, err = strconv.ParseInt(*maxBody, 10, 64)
	if err != nil || opts.maxBodyBytes <= 0 {
		return options{}, fmt.Errorf("invalid max-body-bytes %q: want a positive integer", *maxBody)
	}
	return opts, nil
}

func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) error {
	opts, err := parseOptions(args, getenv, stderr)
	if err != nil {
		return err
	}
	if opts.showVersion {
		fmt.Fprintln(stderr, "promptgate", version)
		return nil
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	handler, err := proxy.New(proxy.Config{
		Upstream:     opts.upstream,
		Mode:         opts.mode,
		MaxBodyBytes: opts.maxBodyBytes,
		Logger:       logger,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              opts.listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: streamed completions can legitimately run long.
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("promptgate listening", "version", version, "listen", opts.listen,
		"upstream", opts.upstream.Redacted(), "mode", string(opts.mode))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}
