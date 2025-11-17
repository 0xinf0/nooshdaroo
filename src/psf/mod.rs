//! PSF (Protocol Shape Format) Interpreter
//!
//! A complete interpreter for PSF files that dynamically generates protocol
//! frame wrapping and unwrapping logic at runtime.
//!
//! Architecture:
//! - Lexer: Tokenizes PSF files into tokens
//! - Parser: Builds AST from tokens
//! - Interpreter: Generates wrap/unwrap functions from AST

pub mod lexer;
pub mod parser;
pub mod interpreter;
pub mod types;

pub use interpreter::PsfInterpreter;
pub use types::{PsfSpec, ProtocolFrame};
