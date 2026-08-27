//! seawall library target — exposes the `mcp` module for integration tests.
//!
//! The `mcp::acvp` sub-module is used by the ACVP KAT integration tests in
//! `tests/acvp_*.rs`. Exposing it via a `lib` target avoids duplicating
//! business logic into test-only modules.

pub mod mcp;
