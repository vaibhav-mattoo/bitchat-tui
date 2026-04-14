# Contributing to bitchat-tui

Welcome! We're glad you're interested in contributing to bitchat-tui.

This document outlines how to contribute effectively and how the project is organized.

## Code of Conduct

Please be respectful and constructive. We're all working together to make secure, off-grid communication accessible to everyone.

## How to Contribute

### 1. Reporting Bugs

Before reporting a bug:
- Search existing issues to see if it's already reported
- If it's a **security vulnerability**, please email the maintainer directly rather than opening an issue

When opening a bug report, include:
- Your operating system and version
- Steps to reproduce the issue
- What you expected to happen vs what actually happened
- Any relevant logs (redact sensitive information)

### 2. Suggesting Features

Open an issue with:
- A clear description of the feature
- Why it's useful (use case)
- If possible, how you'd implement it

### 3. Pull Requests

#### Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch: `git checkout -b my-feature`

#### Making Changes

```bash
# Make your changes, then test them
cargo build
cargo run
```

#### Submitting Your PR

1. Push to your fork: `git push origin my-feature`
2. Open a pull request against `main`
3. Include a clear description of what the PR fixes/changes
4. Link any relevant issues (e.g., "Fixes #3")

#### PR Requirements

- Title should be clear and descriptive
- Keep changes focused - one feature or fix per PR
- Include tests if adding new functionality
- Don't introduce security vulnerabilities

## Project Structure

```
src/
├── main.rs           # Entry point, event loop
├── data_structures.rs   # Protocol data types
├── packet_parser.rs     # Parsing BitChat packets
├── payload_handling.rs  # Message handling
├── noise_protocol.rs   # Noise protocol implementation
├── noise_session.rs   # Session management
├── encryption.rs    # Encryption service
├── notification_handlers.rs  # BLE notifications
├── message_handlers.rs      # Message handlers
├── tui/             # Terminal UI
│   ├── app.rs       # App state
│   ├── event.rs    # Event handling
│   └── widgets/    # UI components
└── binary_protocol_utils.rs  # Binary encoding utilities
```

## Development Tips

### Running in Debug Mode

```bash
# Enable logging
cargo run 2>&1 | tee debug.log
```

### Testing BLE Functionality

You'll need two devices with Bluetooth to test peer-to-peer features.

### Code Style

- Run `cargo fmt` before committing
- Use meaningful variable and function names
- Add comments for complex logic

## Recognizing Contributors

All contributors are acknowledged in the project. By contributing, you agree to let your contribution be included.

## Getting Help

- Open an issue for questions
- Check existing issues before asking
- Be patient - the maintainer responds in their spare time