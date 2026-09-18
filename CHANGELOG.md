# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-18

### Added
- Added full `crates.io` package metadata to `Cargo.toml` including `repository`, `homepage`, `documentation`, `keywords`, and `categories`.
- Added `AGPL-3.0-or-later` license and corresponding `LICENSE` file.
- Introduced `MqttConfig` struct in `transport.rs` to group configuration parameters logically.

### Changed
- **Breaking**: Renamed the crate package name from `deezchatz-sdk-rust` to `deezchatz-sdk` for `crates.io` publishing.
- **Breaking**: Updated `libsignal-dezire` dependency to point to the `0.2.0` published crate instead of a local path.
- **Breaking**: Refactored `MqttService::new` in `transport.rs` to accept the new `MqttConfig` struct, reducing the number of arguments and resolving a `clippy` warning.
- Replaced deep loop nesting in `MqttService`'s background worker with a standalone `process_message` asynchronous helper.
- Fixed outdated crate name references in `lib.rs` doctests.

### Fixed
- Fixed several `needless_borrows_for_generic_args` `clippy` warnings in `crypto.rs` relating to Base64 encoding.
- Fixed a `manual_map` `clippy` warning in `crypto.rs` by streamlining an `if let Some` check.
