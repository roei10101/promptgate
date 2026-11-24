# promptgate

[![CI](https://github.com/roei10101/promptgate/actions/workflows/ci.yml/badge.svg)](https://github.com/roei10101/promptgate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A small security gateway for LLM APIs. promptgate is a reverse proxy that sits
between your applications (or coding agents) and an LLM provider, inspects
every JSON request on the way out, and **blocks or redacts requests that carry
credentials** — before they leave your network.

```
 app / agent ──▶ promptgate ──▶ LLM API
                   │
                   ├─ scan every string in the JSON body
                   ├─ block (403) · redact · monitor
                   └─ structured audit log (never the secret itself)
```

## Why

Prompts are an easy place to leak secrets: a stack trace with a token in it, a
pasted `.env` file, an agent that reads a config file and helpfully includes it
in its context. Once that request is sent, the credential is in a third
party's logs. promptgate puts one enforcement point in front of the provider,
so the control does not depend on every client getting it right.

It is written in Go using only the standard library: one static binary, no
dependencies to audit.

> **Status:** early. The core proxy and the secret detectors work and are
> tested; see the [roadmap](ROADMAP.md) for what is planned and
> [Limitations](#limitations) for what it does not do yet.

## Quick start

Requires Go 1.24 or newer.

```sh
git clone https://github.com/roei10101/promptgate.git
cd promptgate
make build

# Put the gateway in front of any HTTP(S) LLM API, e.g. a local Ollama:
./bin/promptgate -upstream http://localhost:11434
```

Then point your client's base URL at `http://127.0.0.1:8080` instead of the
provider. Paths, query strings, headers (including the client's own
`Authorization` header) and streamed responses pass through unchanged.

A request with a credential in it is stopped:

```sh
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"why is <an AWS access key id> rejected?"}]}'
```

```json
{
  "error": {
    "type": "promptgate_blocked",
    "message": "request blocked: it contains aws_access_key_id",
    "findings": [
      { "detector": "aws_access_key_id", "path": "messages[0].content" }
    ]
  }
}
```

The response names the detector and the JSON path so the caller can fix the
prompt. The matched text is never echoed back and never written to the log.

## Modes

| Mode      | Request with a finding                                    | Response header                 |
|-----------|-----------------------------------------------------------|---------------------------------|
| `block`   | Rejected with `403`; the upstream is never contacted      | `X-Promptgate-Action: blocked`  |
| `redact`  | Each match is replaced by `[REDACTED:<detector>]`, then forwarded | `X-Promptgate-Action: redacted` |
| `monitor` | Forwarded unchanged; the finding is only logged           | `X-Promptgate-Action: monitored`|

`block` is the default. `monitor` is useful for a trial run to see what would
be caught before enforcing.

Requests without findings are forwarded byte for byte. In `redact` mode a
request that is modified is re-encoded, so key order and whitespace may
change; values other than the redacted strings (including large numbers) are
preserved exactly.

## Detectors

| Detector            | Matches                                                         |
|---------------------|-----------------------------------------------------------------|
| `aws_access_key_id` | AWS access key IDs (`AKIA…`, `ASIA…`)                           |
| `github_token`      | GitHub classic (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) and fine-grained (`github_pat_`) tokens |
| `slack_token`       | Slack tokens (`xoxb-`, `xoxp-`, …)                              |
| `llm_api_key`       | Provider API keys in the `sk-…` family                          |
| `jwt`               | JSON Web Tokens                                                 |
| `private_key`       | PEM private keys, including truncated ones                      |

Every pattern targets a format with a vendor-specific prefix or structure, so
false positives stay low enough to block on. There is deliberately no generic
"high-entropy string" rule.

## Configuration

Flags take precedence over environment variables.

| Flag              | Environment variable        | Default          | Meaning                                  |
|-------------------|-----------------------------|------------------|------------------------------------------|
| `-upstream`       | `PROMPTGATE_UPSTREAM`       | — (required)     | Base URL of the LLM API                  |
| `-listen`         | `PROMPTGATE_LISTEN`         | `127.0.0.1:8080` | Address to listen on                     |
| `-mode`           | `PROMPTGATE_MODE`           | `block`          | `block`, `redact` or `monitor`           |
| `-max-body-bytes` | `PROMPTGATE_MAX_BODY_BYTES` | `10485760`       | Largest request body accepted (else `413`) |
| `-version`        |                             |                  | Print the version and exit               |

`GET /healthz` is answered by the gateway itself.

Logs are JSON lines on stderr:

```json
{"time":"…","level":"WARN","msg":"sensitive data in request","action":"block","method":"POST","path":"/v1/chat/completions","detectors":["aws_access_key_id"],"findings":1}
```

## Limitations

promptgate currently protects against *accidental* leaks by well-behaved
clients. Known gaps, most of which are on the roadmap:

- Only bodies with a JSON content type are inspected. Other bodies, malformed
  JSON, and compressed request bodies (`Content-Encoding`) are forwarded
  without inspection.
- Only request bodies are scanned — not headers, URLs or responses.
- JSON object keys are not scanned, only string values.
- The gateway listens on plain HTTP and has no authentication of its own, so
  it binds to loopback by default. Put it behind TLS if you expose it.
- Detection is pattern-based: a secret in an unknown format, or one that is
  encoded or split across messages, is not caught.

## Development

```sh
make lint    # gofmt, go vet and golangci-lint (v2, see .golangci.yml)
make test    # go test -race -cover ./...
make build   # bin/promptgate
```

Layout:

```
cmd/promptgate     command-line entry point, flags, graceful shutdown
internal/detect    Detector interface, built-in secret detectors, redaction
internal/proxy     the gateway handler: JSON inspection + reverse proxy
```

Test fixtures build fake credentials at run time, so the repository never
contains a credential-shaped string.

## License

[MIT](LICENSE)
