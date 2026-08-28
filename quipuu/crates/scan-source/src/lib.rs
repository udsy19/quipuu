//! quipuu-scan-source — tree-sitter source scanner.
//!
//! Loads two-layer rule packs (extract + classify) per D-07 and emits
//! [`Finding`]s for every matching crypto API call.
//!
//! Walking skeleton: Go and Python. Languages are added by dropping a new
//! TOML rule file under `crates/core/data/rules/` and wiring up a grammar
//! in `scanner::language_for`.

pub mod rules;
pub mod scanner;

pub use rules::{ClassifyRule, ExtractRule, Language, RulePack};
pub use scanner::{ScanError, Scanner};
