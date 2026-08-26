//! cryptoscope-cbom — CycloneDX 1.6 / 1.7 CBOM emitter and validator.
//!
//! Maps a [`Vec<Finding>`] plus the [`AlgorithmTable`] into a standards-compliant
//! Cryptography Bill of Materials JSON (per D-01 / D-02 / D-03).
//!
//! Two schemas are embedded at compile time from `data/`:
//! * `bom-1.7.schema.json` — default emission target (ECMA-424 2nd Ed.)
//! * `bom-1.6.schema.json` — opt-in via [`SchemaVersion::V1_6`]
//!
//! Validation is performed against the embedded schema before serialisation
//! returns — invalid output never leaves the emitter.

pub mod emit;
pub mod model;
pub mod validate;

pub use emit::{EmitError, EmitOptions, emit_cbom, emit_cbom_json};
pub use model::{Bom, SchemaVersion};
pub use validate::{ValidationError, validate};
