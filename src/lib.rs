//! anyz: fast all-in-one binary triage for CTF players, reverse engineers and
//! malware analysts.
//!
//! Pipeline:
//! * [`loader`]: magic detection, goblin parsing -> unified [`model::Binary`]
//! * [`analyzers`]: model -> plain, serializable report structs (no printing)
//! * [`render`]: reports -> pretty terminal output, plain text, or JSON

pub mod addr;
pub mod analyzers;
pub mod cli;
pub mod loader;
pub mod model;
pub mod render;
