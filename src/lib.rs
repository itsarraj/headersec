//! `headersec` — grade a live URL's HTTP response security headers.
//!
//! The split matters: [`grade`] holds every rule and is completely pure, so
//! "is a 300-second HSTS max-age a pass?" is answerable by a unit test with
//! no network. [`fetch`] is the only module that opens a socket.

pub mod fetch;
pub mod grade;
pub mod headers;
pub mod report;

pub use grade::{analyze, Assessment, Finding, Grade, Level};
pub use headers::Headers;
