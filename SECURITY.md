# Security policy

promptgate is a security control, so reports about ways around it are
especially welcome.

## Supported versions

Only the latest release and the `main` branch receive fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it
privately through GitHub's
[private vulnerability reporting](https://github.com/roei10101/promptgate/security/advisories/new)
("Report a vulnerability" on the Security tab).

Useful details:

- the promptgate version (`promptgate -version`) and mode (`block`, `redact`, `monitor`);
- a minimal request that reproduces the problem — use fake credentials, never real ones;
- what you expected and what happened.

You can expect an acknowledgement within a week. Once a fix is released, the
advisory is published with credit to the reporter unless you prefer otherwise.

## What counts as a vulnerability

In scope:

- a request that carries a secret matched by a built-in detector and still
  reaches the upstream in `block` or `redact` mode;
- a secret, or part of one, written to the logs or echoed in an error response;
- crashes, unbounded memory use or other denial of service caused by a request;
- request smuggling or header handling that lets a client bypass inspection.

Out of scope are the limitations already documented in the
[README](README.md#limitations), such as credential formats without a detector
or bodies that are not JSON. Ideas for closing those gaps are welcome as
regular issues.
