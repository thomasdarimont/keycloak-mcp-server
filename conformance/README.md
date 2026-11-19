# MCP conformance

[modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance) runs protocol scenarios against
an MCP server. This folder holds everything needed to run it against `keycloak-mcp-server`.

```
./mvnw package -DskipTests      # server + conformance/fixtures
conformance/run.sh              # packaged server with the fixtures on :8085, all scenarios, baseline applied
conformance/run.sh --url http://localhost:8081/mcp   # any running server
```

- `run.sh`: starts the packaged server (no Keycloak needed) with the fixture jar in its `providers/` directory, runs
  the suite with the baseline, exits 0 only when nothing unexpected fails. Reports: `results/`, server log
  `results-server.log`.
- `fixtures/`: a Maven module with the `test_*` tools and prompts the suite calls, built as an extension jar for the
  `providers/` directory. Never ship it. It only covers what the tool model expresses: text and error results, prompts.
- `expected-failures.yml`: what this server fails on purpose, one reason each: a whole scenario, or a single check of
  one (`<scenario>:<check-id>`), so that the other checks of that scenario stay enforced. An entry that starts
  passing fails the run as a stale baseline entry, so the list stays honest. The suite also counts its warnings
  (a `SHOULD` that is not met) against the baseline.

The suite version is set in `run.sh` (`CONFORMANCE_VERSION` overrides it): `0.2.0-alpha.12`, the first line that
covers protocol version `2026-07-28` with its stateless requests and header validation. The last stable release,
`0.1.16`, stops at `2025-06-18`; the baseline file does not fit it any more, as it lacks the single-check form.

## Status

135 checks pass, 65 fail, all of them baselined.

Scenarios that pass: `server-initialize`, `server-session-lifecycle`, `ping`, `logging-set-level`, `tools-list`,
`tools-call-simple-text`, `tools-call-error`, `server-sse-polling`, `server-sse-multiple-streams`, `resources-list`,
`prompts-list`, `prompts-get-simple`, `prompts-get-with-args`, `dns-rebinding-protection`, `caching`,
`http-header-validation`, `http-custom-header-server-validation`, `sep-2640-skills-*`,
`input-required-result-unsupported-methods`, `input-required-result-validate-input`. Of `server-stateless`, 23 of
28 checks pass.

Baselined, by reason:

- Content types the Keycloak tools never produce (image, audio, embedded resource, mixed).
- Client round trips from inside a tool: log and progress notifications, sampling, tool-driven elicitation, and the
  input requests of the stateless protocol (`input-required-result-*`). The server asks the client itself, for
  the confirmation of a destructive tool; the `ToolHandler` SPI has no client channel, so the fixtures cannot provide
  the tools these scenarios call. Four checks of `server-stateless` need such diagnostic tools as well.
- Tasks (`tasks-*`): none. A tool call answers with its result.
- Resources: none. Realm data is reached through tools.
- `completion/complete`: not declared.
- `json-schema-2020-12`: tool schemas are flat by design for small local models; `InputSchema` has no `$defs`/`$ref`.
- From the MCP extension: an error for mismatching headers carries `id: null` instead of the request's id
  (`server-stateless`), no `list_changed` notification on a subscription stream, no `data.uri` in the error for an
  unknown resource (the last two are recommendations).

## Header validation

`http-custom-header-server-validation` found that an `Mcp-Param-*` header with Base64 that cannot be decoded was
accepted (missing padding) or ended as a 500 (characters outside the alphabet). Fixed by `McpParamHeaderCheck`,
which answers 400 with `HeaderMismatch` before the MCP extension reads the header; see
[Tools](../docs/tools.md#http-headers).

## DNS rebinding

`dns-rebinding-protection` found the anonymous localhost server accepting foreign `Host`/`Origin` values. Fixed by
`kc-mcp.mcp.dns-rebinding-protection` (default `auto`: on while the endpoint is anonymous); see [Security](../docs/security.md#guardrails).

## CI

```yaml
- uses: modelcontextprotocol/conformance@v0.2.0-alpha.12
  with:
    mode: server
    url: http://localhost:8085/mcp
    expected-failures: conformance/expected-failures.yml
```

The server must be started with the fixture jar first (see `run.sh`).
