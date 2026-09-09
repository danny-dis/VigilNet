# VigilNet Development Roadmap

**Version:** 1.0  
**Last Updated:** 2026-02-15  
**Status:** Draft

---

## Executive Summary

VigilNet is a privacy-hardened P2P networking engine with 20 Rust crates implementing Signal Protocol E2EE, multi-hop onion routing, and offline mesh networking. This roadmap prioritizes improvements by impact vs. effort to deliver maximum value quickly.

**Current State:**
- 20 crates (~50K LOC)
- 500+ test cases
- 5 platforms supported (Linux x64/ARM64, macOS, Windows, Android)
- Signal Protocol E2EE implemented
- Basic CLI functional

**Key Gaps Identified:**
1. Research system is mocked/stubbed
2. Android Kotlin UI not implemented
3. iOS platform missing
4. No continuous integration
5. Limited benchmarking
6. Security audit pending

---

## 1. Short-Term (0-1 Month) — Quick Wins

### 1.1 Test Suite Hardening 🔧
**Priority:** P0 | **Impact:** High | **Effort:** Low | **Risk:** Low

**Objective:** Achieve 90%+ test coverage and fix any broken tests.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M1.1.1 | Audit all 500+ tests, identify failing tests | Week 1 | TBD |
| M1.1.2 | Fix crypto edge cases (key rotation, large payloads) | Week 2 | TBD |
| M1.1.3 | Add missing integration tests for agent message flow | Week 3 | TBD |
| M1.1.4 | Coverage report ≥90% | Week 4 | TBD |

**Dependencies:** None

**Resource Estimate:** 1 engineer × 4 weeks = 4 person-weeks

**Risk Assessment:**
- Low: Well-defined scope, existing test infrastructure
- Mitigation: Parallelize with other workstreams

**Success Criteria:**
- [ ] `cargo test --workspace` passes 100%
- [ ] Coverage report shows ≥90% line coverage
- [ ] No test timeouts or flaky tests
- [ ] CI badge shows green

---

### 1.2 CLI Polish & Documentation 📝
**Priority:** P0 | **Impact:** High | **Effort:** Low | **Risk:** Low

**Objective:** Production-ready CLI with complete documentation.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M1.2.1 | Add missing CLI commands (`agent stop`, `circle invite`) | Week 1 | TBD |
| M1.2.2 | Implement daemon mode for `start/stop/status` | Week 2 | TBD |
| M1.2.3 | Add progress indicators and colored output | Week 2 | TBD |
| M1.2.4 | Write comprehensive user guide with examples | Week 3 | TBD |
| M1.2.5 | API reference documentation (rustdoc) | Week 4 | TBD |

**Dependencies:** None

**Resource Estimate:** 1 engineer × 4 weeks = 4 person-weeks

**Risk Assessment:**
- Low: CLI framework (clap) already in place
- Mitigation: Incremental delivery

**Success Criteria:**
- [ ] All CLI commands functional and tested
- [ ] `--help` provides useful information for all commands
- [ ] User can complete basic flow without reading code
- [ ] API docs published to docs.rs

---

### 1.3 CI/CD Pipeline 🚀
**Priority:** P1 | **Impact:** High | **Effort:** Medium | **Risk:** Low

**Objective:** Automated testing and releases on every commit.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M1.3.1 | GitHub Actions workflow for Linux/macOS/Windows | Week 1 | TBD |
| M1.3.2 | Cross-compilation for ARM64 targets | Week 2 | TBD |
| M1.3.3 | Android NDK build integration | Week 3 | TBD |
| M1.3.4 | Automated release artifacts (deb, dmg, exe, apk) | Week 4 | TBD |

**Dependencies:** M1.1 (tests must pass)

**Resource Estimate:** 1 DevOps engineer × 3 weeks = 3 person-weeks

**Risk Assessment:**
- Low: Standard GitHub Actions patterns
- Risk: Android NDK setup complexity
- Mitigation: Use cargo-ndk, cache aggressively

**Success Criteria:**
- [ ] Green CI on every PR
- [ ] Release artifacts auto-generated on tag
- [ ] Multi-platform binaries available

---

### 1.4 Configuration Management ⚙️
**Priority:** P1 | **Impact:** Medium | **Effort:** Low | **Risk:** Low

**Objective:** Robust config system with validation and hot-reload.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M1.4.1 | Config validation schema | Week 1 | TBD |
| M1.4.2 | Environment variable overrides | Week 1 | TBD |
| M1.4.3 | Config hot-reload (SIGHUP) | Week 2 | TBD |
| M1.4.4 | Migration tool for config versions | Week 2 | TBD |

**Dependencies:** None

**Resource Estimate:** 0.5 engineer × 2 weeks = 1 person-week

**Success Criteria:**
- [ ] Invalid config rejected with clear error
- [ ] `vigilnet config --validate` command works
- [ ] Config changes apply without restart

---

## 2. Medium-Term (1-3 Months) — Major Features

### 2.1 Research System Implementation 🔬
**Priority:** P0 | **Impact:** Very High | **Effort:** High | **Risk:** Medium

**Objective:** Fully functional multi-perspective research with real LLM integration.

**Current State:** Mock/simulation only (see `main.rs:505-533`)

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M2.1.1 | LLM provider abstraction (OpenAI, Anthropic, local) | Week 1-2 | TBD |
| M2.1.2 | Perspective router with capability matching | Week 3-4 | TBD |
| M2.1.3 | Sub-agent spawning and lifecycle management | Week 5-6 | TBD |
| M2.1.4 | Consensus engine with confidence scoring | Week 7-8 | TBD |
| M2.1.5 | Result aggregation and synthesis | Week 9-10 | TBD |
| M2.1.6 | Web UI for research visualization | Week 11-12 | TBD |

**Dependencies:** 
- M1.1 (test infrastructure)
- M1.2 (CLI daemon mode)
- External: LLM API keys

**Resource Estimate:** 2 engineers × 12 weeks = 24 person-weeks

**Risk Assessment:**
- Medium: LLM integration complexity, rate limits, costs
- Risk: API changes, latency requirements
- Mitigation: 
  - Abstract provider interface for easy swapping
  - Implement caching layer
  - Local LLM fallback (llama.cpp)

**Success Criteria:**
- [ ] `vigilnet research "query"` returns actual LLM-generated analysis
- [ ] Multiple perspectives aggregated with confidence scores
- [ ] Sub-agents spawn and complete in parallel
- [ ] Results stored with audit trail
- [ ] <5s latency for simple queries, <30s for complex

---

### 2.2 Android Kotlin UI (Obsidian) 📱
**Priority:** P0 | **Impact:** Very High | **Effort:** High | **Risk:** Medium

**Objective:** Premium Android VPN app with glassmorphism UI as described in README.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M2.2.1 | Jetpack Compose UI scaffold | Week 1-2 | TBD |
| M2.2.2 | Glassmorphism theme system | Week 3-4 | TBD |
| M2.2.3 | VPN toggle with heartbeat animation | Week 5-6 | TBD |
| M2.2.4 | Multi-hop circuit visualization | Week 7-8 | TBD |
| M2.2.5 | Settings panel with backend selection | Week 9-10 | TBD |
| M2.2.6 | Agent network integration | Week 11-12 | TBD |
| M2.2.7 | Play Store submission prep | Week 13 | TBD |

**Dependencies:**
- M1.3 (CI with Android builds)
- vigilnet-android FFI crate (exists)

**Resource Estimate:** 
- 2 mobile engineers × 13 weeks = 26 person-weeks
- 1 Rust engineer × 4 weeks (FFI integration) = 4 person-weeks

**Risk Assessment:**
- Medium: Complex UI requirements, Android version fragmentation
- Risk: Play Store rejection, performance on low-end devices
- Mitigation:
  - Start with Material 3, customize gradually
  - Test on multiple Android versions (9-14)
  - Early Play Store consultation

**Success Criteria:**
- [ ] App launches without crashes on Android 9-14
- [ ] VPN toggle works with visual feedback
- [ ] Circuit visualization shows current route
- [ ] Settings persist across app restarts
- [ ] <100MB APK size
- [ ] Battery usage <5% per hour

---

### 2.3 Performance Benchmarking 📊
**Priority:** P1 | **Impact:** High | **Effort:** Medium | **Risk:** Low

**Objective:** Comprehensive performance metrics and regression detection.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M2.3.1 | Criterion.rs benchmark suite | Week 1-2 | TBD |
| M2.3.2 | Network throughput benchmarks | Week 3-4 | TBD |
| M2.3.3 | Latency distribution measurements | Week 5-6 | TBD |
| M2.3.4 | Memory profiling and leak detection | Week 7-8 | TBD |
| M2.3.5 | CI performance regression gates | Week 9-10 | TBD |
| M2.3.6 | Public performance dashboard | Week 11-12 | TBD |

**Dependencies:** M1.3 (CI infrastructure)

**Resource Estimate:** 1 engineer × 12 weeks = 12 person-weeks

**Risk Assessment:**
- Low: Standard benchmarking practices
- Risk: Flaky benchmarks in CI
- Mitigation: Statistical analysis, multiple runs

**Success Criteria:**
- [ ] Benchmarks run in <10 minutes
- [ ] 10% regression fails CI
- [ ] Dashboard shows trends over time
- [ ] Memory usage tracked per release

---

### 2.4 Enhanced Error Handling & Observability 💊
**Priority:** P1 | **Impact:** High | **Effort:** Medium | **Risk:** Low

**Objective:** Production-grade observability for debugging and monitoring.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M2.4.1 | Structured logging with tracing | Week 1-2 | TBD |
| M2.4.2 | OpenTelemetry integration | Week 3-4 | TBD |
| M2.4.3 | Metrics export (Prometheus) | Week 5-6 | TBD |
| M2.4.4 | Distributed tracing for circuits | Week 7-8 | TBD |
| M2.4.5 | Health check endpoints | Week 9-10 | TBD |
| M2.4.6 | Alerting rules documentation | Week 11-12 | TBD |

**Dependencies:** None

**Resource Estimate:** 1 engineer × 12 weeks = 12 person-weeks

**Success Criteria:**
- [ ] All errors have structured context
- [ ] Traces show full circuit path
- [ ] Metrics available for Grafana
- [ ] Health endpoint returns 200 when healthy

---

## 3. Long-Term (3-6 Months) — Strategic Initiatives

### 3.1 iOS Platform Support 🍎
**Priority:** P1 | **Impact:** Very High | **Effort:** Very High | **Risk:** High

**Objective:** Full iOS support with NetworkExtension integration.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M3.1.1 | iOS FFI bindings (vigilnet-ios crate) | Month 1 | TBD |
| M3.1.2 | SwiftUI Obsidian UI port | Month 2 | TBD |
| M3.1.3 | NetworkExtension VPN integration | Month 3 | TBD |
| M3.1.4 | App Store submission | Month 4 | TBD |
| M3.1.5 | iOS-specific optimizations | Month 5-6 | TBD |

**Dependencies:**
- M2.2 (Android UI patterns to reuse)
- Apple Developer account
- Mac build machine

**Resource Estimate:**
- 2 iOS engineers × 6 months = 48 person-weeks
- 1 Rust engineer × 2 months (FFI) = 8 person-weeks

**Risk Assessment:**
- High: NetworkExtension complexity, App Store restrictions
- Risk: Rejection due to VPN policy, technical limitations
- Mitigation:
  - Early engagement with Apple Developer Support
  - Implement as "network diagnostics" tool initially
  - Fallback to personal VPN configuration

**Success Criteria:**
- [ ] App runs on iOS 15+
- [ ] VPN connects and routes traffic
- [ ] Passes App Store review
- [ ] Feature parity with Android (80%+)

---

### 3.2 Security Audit & Hardening 🔐
**Priority:** P0 | **Impact:** Critical | **Effort:** High | **Risk:** Medium

**Objective:** Third-party security audit and hardening.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M3.2.1 | Pre-audit self-assessment | Month 1 | TBD |
| M3.2.2 | Third-party crypto audit | Month 2 | TBD |
| M3.2.3 | Network protocol audit | Month 3 | TBD |
| M3.2.4 | Remediation of findings | Month 4 | TBD |
| M3.2.5 | Re-audit verification | Month 5 | TBD |
| M3.2.6 | Security documentation release | Month 6 | TBD |

**Dependencies:**
- M1.1 (tests passing)
- M2.3 (performance baseline)
- Budget for security firm

**Resource Estimate:**
- 1 security engineer × 6 months (internal) = 24 person-weeks
- External audit: $50K-100K

**Risk Assessment:**
- Medium: Potential for critical findings requiring redesign
- Risk: Audit schedule delays, remediation complexity
- Mitigation:
  - Use reputable firm (Trail of Bits, NCC Group)
  - Buffer time for remediation
  - Prioritize crypto audit (highest risk)

**Success Criteria:**
- [ ] No critical vulnerabilities
- [ ] No high-severity unaddressed issues
- [ ] Security report published
- [ ] HackerOne/bug bounty program launched

---

### 3.3 Advanced Mesh Networking 🔗
**Priority:** P2 | **Impact:** Medium | **Effort:** High | **Risk:** Medium

**Objective:** Robust offline mesh with DTN and LoRa integration.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M3.3.1 | BLE mesh protocol optimization | Month 1-2 | TBD |
| M3.3.2 | Meshtastic integration | Month 2-3 | TBD |
| M3.3.3 | DTN message routing algorithms | Month 3-4 | TBD |
| M3.3.4 | Store-and-forward persistence | Month 4-5 | TBD |
| M3.3.5 | Mesh visualization in UI | Month 5-6 | TBD |

**Dependencies:**
- M2.2 (Android UI)
- Hardware: LoRa devices for testing

**Resource Estimate:** 2 engineers × 6 months = 48 person-weeks

**Risk Assessment:**
- Medium: Hardware dependencies, protocol complexity
- Risk: LoRa hardware availability, range limitations
- Mitigation:
  - Partner with Meshtastic community
  - Simulated mesh testing
  - Fallback to Wi-Fi Direct

**Success Criteria:**
- [ ] Messages route through 3+ hops
- [ ] DTN store persists across restarts
- [ ] LoRa bridge tested with real hardware
- [ ] Mesh topology visible in UI

---

### 3.4 Federated Learning Integration 🧠
**Priority:** P2 | **Impact:** Medium | **Effort:** Very High | **Risk:** High

**Objective:** Privacy-preserving federated learning across agent network.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M3.4.1 | FL protocol design | Month 1 | TBD |
| M3.4.2 | Differential privacy integration | Month 2 | TBD |
| M3.4.3 | Secure aggregation | Month 3-4 | TBD |
| M3.4.4 | Model distribution system | Month 4-5 | TBD |
| M3.4.5 | Evaluation framework | Month 6 | TBD |

**Dependencies:**
- M2.1 (research system)
- M3.2 (security audit)
- ML expertise

**Resource Estimate:** 
- 2 ML engineers × 6 months = 48 person-weeks
- 1 Rust engineer × 3 months = 12 person-weeks

**Risk Assessment:**
- High: Complex crypto requirements, performance impact
- Risk: Differential privacy overhead, convergence issues
- Mitigation:
  - Start with simple models (logistic regression)
  - Benchmark before full integration
  - Academic collaboration

**Success Criteria:**
- [ ] FL training converges on test dataset
- [ ] Privacy budget tracked and enforced
- [ ] <2× overhead vs centralized training
- [ ] Paper submitted to conference

---

### 3.5 Enterprise Features 🏢
**Priority:** P2 | **Impact:** Medium | **Effort:** High | **Risk:** Low

**Objective:** SSO, audit trails, and admin controls for enterprise deployment.

| Milestone | Deliverable | ETA | Owner |
|-----------|-------------|-----|-------|
| M3.5.1 | SAML/OIDC integration | Month 1-2 | TBD |
| M3.5.2 | Audit logging system | Month 2-3 | TBD |
| M3.5.3 | Admin dashboard | Month 3-4 | TBD |
| M3.5.4 | Policy enforcement | Month 4-5 | TBD |
| M3.5.5 | SCIM provisioning | Month 5-6 | TBD |

**Dependencies:**
- M2.4 (observability)
- M3.2 (security audit)

**Resource Estimate:** 2 engineers × 6 months = 48 person-weeks

**Success Criteria:**
- [ ] SSO login works with Okta/Entra
- [ ] All actions logged immutably
- [ ] Admin can view all circles/agents
- [ ] Policies enforced at network level

---

## Priority Matrix

| Feature | Impact | Effort | Priority | Timeline |
|---------|--------|--------|----------|----------|
| Test Hardening | High | Low | P0 | Month 1 |
| CLI Polish | High | Low | P0 | Month 1 |
| CI/CD Pipeline | High | Medium | P1 | Month 1 |
| Research System | Very High | High | P0 | Months 2-4 |
| Android UI | Very High | High | P0 | Months 2-4 |
| Performance Benchmarks | High | Medium | P1 | Months 2-4 |
| Observability | High | Medium | P1 | Months 2-4 |
| iOS Support | Very High | Very High | P1 | Months 4-9 |
| Security Audit | Critical | High | P0 | Months 4-9 |
| Advanced Mesh | Medium | High | P2 | Months 4-9 |
| Federated Learning | Medium | Very High | P2 | Months 4-9 |
| Enterprise Features | Medium | High | P2 | Months 4-9 |

---

## Resource Requirements

### Engineering Staff (FTE)

| Phase | Rust | Mobile | DevOps | Security | ML | Total |
|-------|------|--------|--------|----------|-----|-------|
| Month 1 | 1.0 | 0.5 | 1.0 | 0.0 | 0.0 | 2.5 |
| Months 2-3 | 2.0 | 2.0 | 0.5 | 0.0 | 0.0 | 4.5 |
| Months 4-6 | 2.0 | 2.0 | 0.5 | 1.0 | 1.0 | 6.5 |

**Total Person-Months:** 22.5 FTE-months (6 months)

### Budget Estimates

| Category | Cost |
|----------|------|
| Engineering (22.5 months @ $15K/mo) | $337,500 |
| Security Audit | $75,000 |
| CI/CD Infrastructure | $5,000 |
| LLM API Credits | $10,000 |
| Test Devices (Android/iOS) | $5,000 |
| Apple Developer Program | $100 |
| **Total** | **$432,600** |

---

## Risk Summary

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| LLM API changes | Medium | Medium | Abstract provider, local fallback |
| App Store rejection | Medium | High | Early consultation, fallback positioning |
| Security audit findings | High | Medium | Buffer time, prioritize crypto |
| Team scaling delays | Medium | Medium | Start with core features, contract help |
| Android fragmentation | High | Low | Test matrix, CI automation |
| iOS NetworkExtension limits | Medium | High | Prototype early, alternative approaches |

---

## Key Performance Indicators (KPIs)

### Technical Metrics

| Metric | Current | 1 Month | 3 Months | 6 Months |
|--------|---------|---------|----------|----------|
| Test Coverage | 70% | 90% | 90% | 95% |
| CI Pass Rate | N/A | 95% | 98% | 99% |
| Release Frequency | Manual | Weekly | Bi-weekly | Weekly |
| P0 Bugs | Unknown | 0 | 0 | 0 |
| Avg Build Time | N/A | <10min | <10min | <5min |

### User Metrics

| Metric | 3 Months | 6 Months |
|--------|----------|----------|
| Android Downloads | 1,000 | 10,000 |
| Active Agents | 100 | 1,000 |
| Research Queries | 500 | 5,000 |
| GitHub Stars | 500 | 2,000 |

---

## Appendix A: Detailed Dependencies Graph

```
M1.1 Test Hardening
    ├── M1.3 CI/CD Pipeline
    └── M2.1 Research System
    
M1.2 CLI Polish
    └── M2.1 Research System
    
M1.3 CI/CD Pipeline
    ├── M2.2 Android UI
    └── M2.3 Performance Benchmarks
    
M2.1 Research System
    ├── M3.4 Federated Learning
    └── M3.5 Enterprise Features
    
M2.2 Android UI
    ├── M3.1 iOS Support
    └── M3.3 Advanced Mesh
    
M2.4 Observability
    └── M3.5 Enterprise Features
    
M3.2 Security Audit
    ├── M3.4 Federated Learning
    └── M3.5 Enterprise Features
```

---

## Appendix B: Definition of Done

### For All Features

- [ ] Code complete and reviewed
- [ ] Tests written (unit + integration)
- [ ] Documentation updated
- [ ] CI passing
- [ ] Benchmarked (if performance-critical)
- [ ] Security review (if crypto-related)

### For Releases

- [ ] All P0 features complete
- [ ] Test coverage ≥90%
- [ ] No known P0/P1 bugs
- [ ] Security audit passed
- [ ] Performance regression <5%
- [ ] CHANGELOG.md updated
- [ ] Git tag created
- [ ] Release notes published

---

## Appendix C: Communication Plan

| Stakeholder | Frequency | Channel | Content |
|-------------|-----------|---------|---------|
| Core Team | Daily | Slack | Blockers, decisions |
| Contributors | Weekly | GitHub Discussions | Progress, RFCs |
| Users | Bi-weekly | Blog/Mastodon | Release notes, features |
| Enterprise | Monthly | Email | Roadmap updates |
| Security | As needed | Encrypted email | Audit results |

---

**Next Review Date:** 2026-03-15

**Document Owner:** TBD

**Approval:**
- [ ] Technical Lead
- [ ] Product Lead
- [ ] Security Lead
