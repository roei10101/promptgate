# Roadmap

promptgate grows in small, tested steps. Each item is meant to be one focused
change that leaves `main` green. Items are done roughly in order; the list is
revised as the design becomes clearer.

## Milestone 1 — Core gateway

- [x] Reverse proxy to a configurable upstream, with streaming pass-through
- [x] Detector interface and built-in secret detectors (AWS, GitHub, Slack, LLM API keys, JWT, PEM private keys)
- [x] JSON body inspection with `block`, `redact` and `monitor` modes
- [x] Health endpoint, structured logs, graceful shutdown
- [x] CI: gofmt, vet, race-enabled tests, build
- [x] Run golangci-lint in CI
- [ ] Request IDs: generate or propagate `X-Request-Id` and include it in logs and error responses
- [ ] Access log line per request (method, path, status, duration, bytes)
- [ ] Inspect compressed request bodies (`Content-Encoding: gzip`)
- [ ] Decide and document the policy for bodies that cannot be inspected (fail-open vs. fail-closed flag)

## Milestone 2 — Detection depth

- [ ] More credential detectors (Google API keys, Stripe keys, npm/PyPI tokens, database URLs with passwords)
- [ ] PII detectors: e-mail addresses, phone numbers, payment card numbers with Luhn check
- [ ] Per-detector actions (e.g. block private keys, redact e-mail addresses)
- [ ] Allow-list for known-safe values (test keys, documentation examples)
- [ ] Prompt-injection heuristics for tool results and retrieved documents
- [ ] Scan responses, including streamed (SSE) responses, for leaked system-prompt canaries
- [ ] Benchmarks for the detectors and the proxy hot path

## Milestone 3 — Policy and configuration

- [ ] Configuration file (JSON) with validation and a `promptgate check-config` command
- [ ] Multiple upstreams with path- or host-based routing
- [ ] Policies per route and per client
- [ ] Model allow-list (reject requests for models that are not approved)
- [ ] Hot reload of configuration on SIGHUP

## Milestone 4 — Access control and limits

- [ ] Gateway API keys for clients (hashed at rest), separate from the upstream credential
- [ ] Inject the upstream credential at the gateway so clients never hold it
- [ ] Rate limiting per client (token bucket)
- [ ] Token and request budgets per client
- [ ] TLS listener

## Milestone 5 — Observability

- [ ] Prometheus metrics endpoint (requests, findings by detector, latency histograms, upstream errors)
- [ ] Audit log as a separate tamper-evident JSONL stream (hash-chained)
- [ ] Example Grafana dashboard
- [ ] OpenTelemetry traces

## Milestone 6 — Packaging and deployment

- [ ] Dockerfile (distroless, non-root) and image build in CI
- [x] Tagged releases with cross-compiled binaries and checksums
- [ ] Kubernetes manifests with probes, resource limits and a NetworkPolicy
- [ ] Helm chart
- [ ] SBOM and image vulnerability scan in CI
- [ ] End-to-end test against a local model server in CI
