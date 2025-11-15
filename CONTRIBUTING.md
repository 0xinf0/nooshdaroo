# Contributing to Nooshdaroo

Thank you for your interest in contributing to Nooshdaroo! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and constructive
- Focus on what is best for the community
- Show empathy towards other contributors

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:

1. A clear, descriptive title
2. Steps to reproduce the issue
3. Expected behavior vs actual behavior
4. Your environment (OS, Rust version, etc.)
5. Relevant logs or error messages

### Suggesting Features

Feature requests are welcome! Please include:

1. Clear description of the feature
2. Use cases and benefits
3. Potential implementation approach (if known)

### Pull Requests

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Test** your changes thoroughly
5. **Commit** with clear messages
6. **Push** to your fork
7. **Open** a pull request

#### Pull Request Guidelines

- Follow Rust coding conventions
- Include tests for new features
- Update documentation as needed
- Keep commits focused and atomic
- Write clear commit messages

## Development Setup

### Prerequisites

- Rust 1.70 or later
- Cargo
- Git

### Building

```bash
# Clone the repository
git clone https://github.com/0xinf0/Nooshdaroo.git
cd Nooshdaroo

# Build debug version
cargo build

# Build release version
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- client --bind 127.0.0.1:1080 --server example.com:8443
```

### Code Style

We follow standard Rust conventions:

```bash
# Format code
cargo fmt

# Check for issues
cargo clippy

# Run all checks
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

## Project Structure

```
nooshdaroo/
├── src/
│   ├── lib.rs          # Library entry point
│   ├── main.rs         # CLI entry point
│   ├── config.rs       # Configuration
│   ├── library.rs      # Protocol library
│   ├── protocol.rs     # Protocol definitions
│   ├── proxy.rs        # Proxy implementations
│   ├── shapeshift.rs   # Shape-shifting logic
│   ├── strategy.rs     # Selection strategies
│   ├── traffic.rs      # Traffic shaping
│   ├── socat.rs        # Relay mode
│   └── mobile.rs       # Mobile bindings
├── protocols/          # Protocol definitions (.psf files)
├── examples/           # Example configurations
└── tests/             # Integration tests
```

## Adding New Protocols

To add a new protocol:

1. Create a `.psf` (Protocol Signature File) in the appropriate `protocols/` subdirectory
2. Follow this format:

```
protocol https {
    name = "HTTPS"
    version = "1.1"
    transport = "TCP"
    default_port = 443
    detection_score = "High"

    handshake {
        pattern = "16 03 01 .."
        offset = 0
    }

    timing {
        initial_delay_ms = [50, 150]
        packet_interval_ms = [10, 50]
    }

    traffic {
        size_distribution = "normal"
        mean_bytes = 1200
        std_dev_bytes = 300
    }
}
```

3. Test the protocol with: `cargo run -- protocols --dir protocols`

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

### Integration Tests

```bash
# Test client/server connection
cargo run -- server --bind 127.0.0.1:8443 &
cargo run -- client --bind 127.0.0.1:1080 --server 127.0.0.1:8443

# Test with curl
curl --socks5 127.0.0.1:1080 https://example.com
```

## Documentation

- Use doc comments (`///`) for public APIs
- Include examples in doc comments
- Update README.md for user-facing changes
- Add technical details to NOOSHDAROO_DESIGN.md

Example:

```rust
/// Create a new Nooshdaroo client
///
/// # Example
///
/// ```rust
/// use nooshdaroo::{NooshdarooConfig, NooshdarooClient};
///
/// let config = NooshdarooConfig::default();
/// let client = NooshdarooClient::new(config)?;
/// ```
///
/// # Errors
///
/// Returns an error if protocol library cannot be loaded
pub fn new(config: NooshdarooConfig) -> Result<Self, NooshdarooError> {
    // ...
}
```

## Commit Message Guidelines

Follow conventional commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

Examples:

```
feat(proxy): add WebSocket proxy support

Implement WebSocket proxy mode to support WS/WSS connections
through the shape-shifting proxy.

Closes #123
```

```
fix(shapeshift): correct protocol rotation timing

The adaptive strategy was not correctly calculating rotation
intervals. This fix ensures proper timing based on traffic patterns.
```

## Release Process

Releases are handled by maintainers:

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create and push tag: `git tag -a v0.2.0 -m "Release v0.2.0"`
4. GitHub Actions will build and publish release

## Questions?

- Open an issue for questions about contributing
- Check existing issues and pull requests
- Review the documentation in the repo

## License

By contributing, you agree that your contributions will be licensed under the same dual MIT OR Apache-2.0 license that covers the project.
