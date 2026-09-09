# VigilNet QA Plan - Quick Reference

## Running Tests

### Unit Tests
```bash
# Run all unit tests
cargo test --workspace --lib

# Run tests for specific crate
cargo test -p vigilnet-crypto --lib

# Run with output
cargo test --workspace --lib -- --nocapture

# Run with coverage
cargo tarpaulin --workspace --lib --out Html
```

### Integration Tests
```bash
# Run all integration tests
cargo test --workspace --test '*'

# Run specific integration test
cargo test --test e2e -- user_onboarding

# Run with environment
docker-compose -f tests/e2e/docker-compose.yml up -d
cargo test --workspace --test e2e
docker-compose -f tests/e2e/docker-compose.yml down
```

### Security Tests
```bash
# Run security audit
cargo audit
cargo deny check

# Run semgrep
semgrep --config .semgrep/security.yml

# Run fuzz tests (requires nightly)
cargo +nightly fuzz run message_parser
cargo +nightly fuzz run crypto_operations

# Run miri (memory safety)
cargo +nightly miri test -p vigilnet-crypto --lib
```

### Performance Tests
```bash
# Run benchmarks
cargo bench --workspace

# Run specific benchmark
cargo bench x3dh

# Profile with flamegraph
cargo flamegraph --bench benchmarks
```

## Coverage Requirements

| Component | Line Coverage | Critical Paths |
|-----------|---------------|----------------|
| vigilnet-crypto | 95% | 100% |
| vigilnet-agent-* | 85-90% | 100% |
| vigilnet-core | 85% | 100% |
| Others | 80% | 100% |

## CI Pipeline Stages

1. **Lint** - Format, clippy, cargo-deny (2-3 min)
2. **Audit** - Security scan (1-2 min)
3. **Unit Tests** - Per platform (5-10 min)
4. **Crypto Tests** - Cryptographic verification (3-5 min)
5. **Integration Tests** - Cross-crate (10-15 min)
6. **Cross Compile** - Multi-platform (5-10 min)
7. **E2E Tests** - Full workflows (Nightly)
8. **Performance Tests** - Benchmarks (Nightly)
9. **Security Tests** - Fuzzing, miri (Weekly)
10. **Release** - Build & deploy (On tag)

## Quality Gates

- **Pre-commit**: Unit tests pass, lint clean
- **PR Merge**: Integration tests pass, 80% coverage
- **Release**: E2E tests pass, security audit, 85% coverage
- **Production**: All tests pass, performance benchmarks met

## Defect Severity

| Level | SLA | Examples |
|-------|-----|----------|
| P0 - Critical | 4 hours | Crypto failure, key leak |
| P1 - High | 24 hours | Connection failures, crashes |
| P2 - Medium | 1 week | Performance degradation |
| P3 - Low | 2 weeks | UI issues, typos |

## Test Environment Variables

```bash
# Network configuration
export TOR_SOCKS_PROXY=socks5://localhost:9050
export I2P_SAM_BRIDGE=localhost:7656
export BOOTSTRAP_NODES=/dns4/localhost/tcp/10001

# Test configuration
export RUST_TEST_THREADS=4
export RUST_LOG=debug
export TEST_TIMEOUT=30

# CI configuration
export CI=true
export COVERAGE_THRESHOLD=85
```

## Test Data Locations

```
tests/
├── data/
│   ├── crypto/          # Cryptographic test vectors
│   ├── network/         # Network topologies
│   └── compliance/      # HIPAA/GDPR test data
├── utils/               # Test utilities
├── integration/         # Integration tests
└── e2e/                 # E2E tests
```

## Useful Commands

```bash
# Check test coverage
cargo tarpaulin --workspace --out Stdout

# Watch tests during development
cargo watch -x "test --workspace --lib"

# Find slow tests
cargo test --workspace --lib -- --report-time

# Run tests with backtrace
cargo test --workspace --lib -- --nocapture
RUST_BACKTRACE=1 cargo test ...

# Check for unsafe code
cargo geiger --all-features

# Update dependencies
cargo update
cargo outdated

# Security audit
cargo audit
cargo deny check advisories
```

## Contact

- QA Lead: qa@vigilnet.io
- Security Team: security@vigilnet.io
- CI/CD Issues: devops@vigilnet.io
