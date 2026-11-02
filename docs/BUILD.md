# Building the backend

Use Linux, Node.js 22 or newer and the Rust version in `build-config.json`.
Native dependencies: a C/C++ toolchain, CMake, pkg-config, OpenSSL development headers, protobuf compiler, D-Bus development headers/daemon, GLib, Git, tar and xz.
Ubuntu 22.04 packages are `build-essential cmake pkg-config libssl-dev protobuf-compiler libdbus-1-dev dbus-daemon libglib2.0-0 tar xz-utils`.
The supported CLI uses the launcher's sign-in UI and builds with `--no-default-features`.

```sh
node --test scripts/ci/*.test.mjs
node scripts/test-backend.mjs
cargo build --locked --release --no-default-features -p xodus-cli -p xodus-service
```

The native tests use synthetic credentials, loopback endpoints and private test buses. Do not run `xodus-service --help`: the service starts authentication instead of parsing help.

From a clean committed checkout, produce a package with:

```sh
node scripts/build-backend.mjs --work ../backend-build --output ../backend-release
```

The work and output directories must not exist. `--target-dir` selects a reusable Cargo cache; `--offline` requires dependencies already cached. CPU parallelism defaults to all available processors; `CARGO_BUILD_JOBS` overrides it.

Each architecture produces a binary archive, a corresponding-source archive containing vendored dependencies and offline Cargo configuration, SHA-512 files, and a manifest identifying the exact backend commit, build configuration, architecture and binary hashes. Build the source archive offline from `source/` using the Cargo command above with `--offline`.

CI runs checks on PRs and development branches. Distribution candidates are built only on `main`, using Ubuntu 22.04 for x86_64 and ARM64. A `[source-only]` main integration runs checks without packaging candidates. Runtime and launcher versions are independent of the backend package version.

Promotion requires a successful main candidate and explicit digest-bound approval in `.github/release-validation.json`, including approved release notes. The manual release workflow publishes the same checked bytes under `backend-v<version>` without rebuilding. Existing tags and assets are never replaced. Increase the package version before publishing changed bytes.
