# Changelog

All notable changes to `zentinel-agent-sdk` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This crate is pre-1.0, so a minor bump may carry breaking changes.

## [Unreleased]

### Fixed

- **Per-request memory leak in `AgentHandler` correlation cache.** Entries are
  released after response headers (and after the final response body chunk when
  response body inspection is declared), on `RequestComplete`, via bounded TTL
  sweep ([`REQUEST_CACHE_MAX_AGE`](https://docs.rs/zentinel-agent-sdk/latest/zentinel_agent_sdk/constant.REQUEST_CACHE_MAX_AGE.html)),
  and at a fixed cap ([`REQUEST_CACHE_MAX_ENTRIES`](https://docs.rs/zentinel-agent-sdk/latest/zentinel_agent_sdk/constant.REQUEST_CACHE_MAX_ENTRIES.html))
  without LRU eviction.

### Changed

- **Fail-closed on correlation cache miss.** `on_request_body_chunk`,
  `on_response_headers`, and `on_response_body_chunk` now return **403 Forbidden**
  when the correlation ID is unknown (evicted or never cached) instead of
  silently allowing. Migration: declare only the [`EventType`] values you handle
  via [`AgentHandler::with_capabilities`] so the SDK does not retain state for
  unused events; ensure body/response hooks run before the cache is released.
- Default negotiated capabilities remain headers-only; correlation state is
  cached only when additional events are declared.

## [0.3.0] - 2026-08-21

The v2 agent protocol rewrite, released. **0.2.0 does not compile against any
current `zentinel-agent-protocol` release** — if you are on 0.2.0, this upgrade
is not optional.

### Changed

- **BREAKING — built on the v2 agent protocol.** The SDK now implements
  `zentinel_agent_protocol::v2::AgentHandlerV2` and targets
  `zentinel-agent-protocol` 0.6.

  The v1 protocol was removed from `zentinel-agent-protocol` in 26.02, but the
  SDK's rewrite was never published. Published 0.2.0 still imports `AgentServer`,
  `AgentHandler`, `ConfigureEvent` and a crate-root `PROTOCOL_VERSION` — all of
  which no longer exist — so it fails to build with `E0432`/`E0433`/`E0405`
  against protocol 0.5.13 or later. 0.3.0 is the first release that builds.

- `zentinel-agent-protocol` dependency: `0.5` → `0.6`.

### Fixed

- `repository` metadata pointed at `zentinelproxy/zentinel-agent-sdk`, which does
  not exist. It now points at
  [`zentinelproxy/zentinel-agent-rust-sdk`](https://github.com/zentinelproxy/zentinel-agent-rust-sdk),
  so the crates.io and docs.rs links resolve.

### Upgrading from 0.2.0

Agents implement `AgentHandlerV2` rather than the v1 `AgentHandler`. The v2
protocol adds a `capabilities()` method, and event types moved under the
protocol crate's `v2` module. See the
[v2 protocol documentation](https://docs.zentinelproxy.io/agents/v2/) and the
[migration notes](https://docs.zentinelproxy.io/agents/v2/migration/) for the
full API surface.

## [0.2.0]

Last release built on the v1 agent protocol. Retained for history; it cannot be
built against current protocol releases.