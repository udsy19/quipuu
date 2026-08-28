//! quipuu-tui — ratatui-based terminal UI.
//!
//! Public surface:
//!   * [`Tui`] — construct with findings + algorithm table + policy, then call `.run()`.
//!   * [`TuiError`] — I/O and no-TTY errors.
//!
//! Internal modules keep rendering logic pure and testable without a real
//! terminal. Only [`app`] touches crossterm / ratatui terminal setup.

pub mod app;
pub mod event;
pub mod model;
pub mod render;
pub mod state;

use quipuu_core::{AlgorithmTable, Finding, Policy};
use thiserror::Error;

pub use state::AppState;

/// Public errors surfaced from the TUI event loop.
#[derive(Debug, Error)]
pub enum TuiError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Returned when the terminal cannot enter raw mode (e.g. CI environment).
    /// The CLI should catch this and fall back to headless output.
    #[error("no TTY available: {0}")]
    NoTty(String),
}

/// Top-level TUI application.
pub struct Tui {
    pub(crate) findings: Vec<Finding>,
    pub(crate) algorithms: AlgorithmTable,
    pub(crate) policy: Policy,
    pub(crate) state: AppState,
}

impl Tui {
    /// Construct the TUI from a set of findings, the algorithm catalogue, and
    /// the active policy.
    pub fn new(findings: Vec<Finding>, algorithms: AlgorithmTable, policy: Policy) -> Self {
        let state = AppState::new(&findings, &policy);
        Self {
            findings,
            algorithms,
            policy,
            state,
        }
    }

    /// Run the event loop on stdout. Blocks until the user quits.
    ///
    /// Returns [`TuiError::NoTty`] when the process is not attached to a
    /// terminal (CI, pipe, etc.).
    pub fn run(self) -> Result<(), TuiError> {
        app::run(self)
    }
}
