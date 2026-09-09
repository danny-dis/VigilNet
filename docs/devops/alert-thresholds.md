# VigilNet Alert Thresholds

**Version:** 1.0.0  
**Last Updated:** 2026-02-15  
**Status:** Production Ready

---

## Severity Levels

| Level | Priority | Response Time | Notification Channel | Escalation |
|-------|----------|---------------|---------------------|------------|
| **Critical (P1)** | Immediate | 15 minutes | Page + Slack + Email | Auto-escalate to on-call lead after 30 min |
| **Warning (P2)** | High | 1 hour | Slack + Email | Escalate to on-call after 2 hours |
| **Info (P3)** | Medium | 4 hours | Slack | Create ticket |
| **Low (P4)** | Low | 24 hours | Slack | Backlog |

---

## Core Service Alerts

### Service Availability

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Service Down | N/A | `up == 0` | 1m | Page on-call immediately |
| Health Check Failures | > 5% | > 20% | 5m | Investigate node health |
| Uptime SLA | < 99.9% | < 99% | 1h | Review recent deployments |

### Error Rates

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Overall Error Rate | > 1% | > 5% | 5m | Check logs, identify pattern |
| API Error Rate | > 2% | > 10% | 3m | Check API gateway health |
| Authentication Failures | > 5% | > 20% | 5m | Potential attack vector |
| Agent Message Failures | > 1% | > 5% | 5m | Check agent connectivity |

### Latency

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Request Latency (p50) | > 100ms | > 500ms | 5m | Check resource utilization |
| Request Latency (p95) | > 500ms | > 2s | 5m | Scale resources or investigate |
| Request Latency (p99) | > 1s | > 5s | 3m | Emergency investigation |
| Encryption Latency | > 1ms | > 10ms | 5m | Check crypto performance |
| Circuit Build Time | > 10s | > 30s | 10m | Check Tor/I2P connectivity |

---

## Resource Utilization

### CPU

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| CPU Usage | > 70% | > 90% | 5m | Scale horizontally |
| CPU Throttling | > 5% | > 20% | 5m | Increase CPU limits |
| Load Average | > 4 | > 8 | 10m | Investigate processes |

### Memory

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Memory Usage | > 80% | > 95% | 5m | Scale or optimize |
| Memory Growth Rate | > 50%/hour | > 100%/hour | 30m | Check for leaks |
| OOM Events | N/A | > 0 | 0m | Immediate investigation |
| Swap Usage | > 10% | > 50% | 5m | Add memory or reduce load |

### Disk

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Disk Usage | > 80% | > 90% | 5m | Clean up or expand |
| Disk I/O Saturation | > 70% | > 90% | 10m | Check storage performance |
| Inode Usage | > 80% | > 95% | 5m | Clean up small files |
| Log Disk Usage | > 70% | > 85% | 5m | Rotate logs |

### Network

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Network Errors | > 0.1% | > 1% | 5m | Check NIC/connection |
| Packet Loss | > 0.1% | > 1% | 5m | Check network path |
| Connection Exhaustion | > 80% capacity | > 95% capacity | 5m | Increase limits |
| Bandwidth Saturation | > 70% | > 90% | 10m | Upgrade bandwidth |

---

## P2P Network

### Peer Connectivity

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Connected Peers | < 3 | < 1 | 10m / 5m | Check bootstrap nodes |
| Peer Connection Rate | > 10/min (spike) | N/A | 5m | Possible DDoS |
| Peer Drop Rate | > 5%/min | > 20%/min | 5m | Network instability |
| Average Peer Latency | > 200ms | > 1s | 10m | Check network quality |

### Protocol Health

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| QUIC Connections | < 10 | < 1 | 10m | Check UDP/firewall |
| TCP Connections | < 5 | < 1 | 10m | Check TCP/firewall |
| Circuit Build Success | < 90% | < 70% | 10m | Check anonymity network |
| DHT Query Success | < 95% | < 80% | 10m | DHT bootstrap issue |
| Bandwidth per Peer | > 10 MB/s | > 50 MB/s | 5m | Possible abuse |

---

## Agent Network

### Agent Health

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Active Agents | < 10 | 0 | 30m / 2m | Check agent service |
| Agent Registration Rate | Spike > 100/hour | N/A | 5m | Possible abuse |
| Agent Timeout Rate | > 5% | > 20% | 10m | Network issues |
| Agent Memory Usage | > 500MB | > 1GB | 5m | Memory leak suspected |

### Message Health

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Message Delivery Rate | < 99% | < 95% | 5m | Queue backup |
| Message Queue Depth | > 1000 | > 10000 | 5m | Consumer lag |
| Message Processing Time | > 100ms | > 1s | 5m | Slow consumers |
| E2EE Handshake Success | < 95% | < 80% | 5m | Crypto issues |
| PreKey Bundle Availability | < 50 | < 10 | 10m | Regenerate keys |

### Circle Health

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Circle Message Latency | > 500ms | > 2s | 5m | Circle sync issues |
| Member Sync Failures | > 1% | > 5% | 10m | Membership issues |
| Invite Validation Failures | > 5% | > 20% | 5m | Security concern |

---

## Security

### Authentication & Access

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Failed Auth Attempts | > 10/min | > 100/min | 5m | Rate limit / investigate |
| Unauthorized Access Attempts | > 5/hour | > 50/hour | 1m | Security incident |
| Token Validation Failures | > 1% | > 5% | 5m | Clock skew or attack |
| Certificate Expiry | < 7 days | < 1 day | 1h / 1m | Renew certificates |

### Threat Detection

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Firewall Blocks | > 50/min | > 500/min | 5m | DDoS suspected |
| Rate Limit Hits | > 100/min | > 1000/min | 5m | Potential abuse |
| Suspicious Patterns | Detected | N/A | 1m | Security review |
| Encryption Anomalies | > 1% | > 5% | 5m | Possible MITM |
| Key Rotation Failures | > 0 | > 5 | 10m | Crypto system issue |

---

## Infrastructure

### Kubernetes

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Pod Restarts | > 2/hour | > 10/hour | 5m | Check crash logs |
| Pod OOMKilled | N/A | > 0 | 0m | Increase memory |
| Pod CrashLoopBackOff | N/A | Detected | 0m | Fix config or bug |
| Node Not Ready | N/A | Detected | 5m | Infrastructure issue |
| PV Usage | > 80% | > 95% | 5m | Expand volumes |
| Image Pull Failures | > 0 | > 5 | 5m | Registry issue |

### Docker/Container

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Container CPU Throttling | > 10% | > 50% | 5m | Increase limits |
| Container Memory Limit | > 90% | N/A | 5m | Scale or optimize |
| Container Exit Code ≠ 0 | Detected | > 5 | 5m | Application error |
| Container Age | > 30 days | N/A | N/A | Scheduled restart |

### Database (if applicable)

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Connection Pool Usage | > 70% | > 90% | 5m | Increase pool size |
| Query Latency (p95) | > 100ms | > 1s | 5m | Optimize queries |
| Slow Queries | > 10/min | > 100/min | 10m | Query optimization |
| Replication Lag | > 1s | > 10s | 5m | Check replication |
| Deadlock Rate | > 1/hour | > 10/hour | 5m | Transaction review |

---

## Anonymity Networks

### Tor

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Tor Circuit Build Time | > 5s | > 30s | 10m | Check Tor network |
| Tor Circuit Failure Rate | > 10% | > 30% | 10m | Bridge fallback |
| Tor Bootstrap Progress | < 100% | Stuck | 10m | Restart Tor client |
| Bridge Connectivity | < 3 bridges | < 1 bridge | 10m | Update bridges |

### I2P

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| I2P Tunnel Build Time | > 10s | > 60s | 10m | Check I2P network |
| I2P Participating Tunnels | < 100 | < 10 | 10m | Bandwidth contribution |
| I2P SAM Connection | Failed | N/A | 5m | Restart I2P service |

### Nym

| Metric | Warning | Critical | Duration | Action |
|--------|---------|----------|----------|--------|
| Nym Gateway Latency | > 500ms | > 2s | 10m | Switch gateway |
| Nym Mixnet Coverage | < 90% | < 70% | 10m | Network issues |
| Nym Coconut Credential | Expiring | Expired | 1h | Renew credentials |

---

## Custom Thresholds by Environment

### Development

| Metric | Warning | Critical |
|--------|---------|----------|
| Error Rate | > 10% | > 50% |
| Latency (p95) | > 2s | > 10s |
| CPU Usage | > 85% | > 95% |
| Peer Count | < 1 | N/A |

### Staging

| Metric | Warning | Critical |
|--------|---------|----------|
| Error Rate | > 5% | > 20% |
| Latency (p95) | > 1s | > 5s |
| CPU Usage | > 75% | > 90% |
| Peer Count | < 2 | < 1 |

### Production

| Metric | Warning | Critical |
|--------|---------|----------|
| Error Rate | > 1% | > 5% |
| Latency (p95) | > 500ms | > 2s |
| CPU Usage | > 70% | > 90% |
| Peer Count | < 3 | < 1 |

---

## Alert Routing Rules

### By Severity

```yaml
# Critical (P1)
- Match: severity=critical
  Channels: [pagerduty, slack-critical, email-oncall]
  Escalation: 30min -> team lead

# Warning (P2)
- Match: severity=warning
  Channels: [slack-warnings, email-team]
  Escalation: 2hours -> on-call

# Info (P3)
- Match: severity=info
  Channels: [slack-info]
  Escalation: None

# Low (P4)
- Match: severity=low
  Channels: [slack-backlog]
  Escalation: None
```

### By Team

```yaml
platform:
  - ServiceDown
  - HighErrorRate
  - HighLatency
  - OOMKilled
  - HighCPUUsage
  - HighMemoryUsage

networking:
  - NoPeersConnected
  - CircuitBuildFailures
  - DHTDegraded
  - HighBandwidth

agents:
  - AgentMessageFailures
  - NoActiveAgents
  - LowAgentActivity

security:
  - SuspiciousActivity
  - AgentAuthFailures
  - RateLimiting
  - FirewallBlocks
```

### Time-Based Routing

```yaml
# Business hours (09:00-18:00 UTC)
business_hours:
  P1: pagerduty + slack + email
  P2: slack + email

# After hours (18:00-09:00 UTC)
after_hours:
  P1: pagerduty only
  P2: slack only (no page)

# Weekends
weekends:
  P1: pagerduty only
  P2: slack only
```

---

## Threshold Tuning Guidelines

### When to Adjust Thresholds

1. **Too Many False Positives**
   - Increase threshold or duration
   - Add additional conditions
   - Review during business hours only

2. **Missed Real Issues**
   - Decrease threshold or duration
   - Add severity escalation
   - Create more specific alerts

3. **Seasonal Patterns**
   - Document expected variations
   - Use dynamic thresholds if available
   - Create time-based overrides

4. **Post-Incident Review**
   - Update thresholds based on lessons learned
   - Add new alerts for detected gaps
   - Remove alerts that didn't help

### Tuning Process

```
1. Collect baseline metrics (1-2 weeks)
2. Identify normal operating ranges
3. Set initial thresholds at p99 of normal
4. Monitor for 1 week
5. Adjust based on false positive rate
6. Document final thresholds
7. Review monthly
```

---

## Appendix: Quick Reference

### Emergency Contacts

| Role | Contact | Escalation Time |
|------|---------|----------------|
| On-Call Engineer | PagerDuty | 24/7 |
| DevOps Lead | Slack: @devops-lead | Immediate |
| Security Team | security@vigilnet.io | Immediate |
| Platform Team | #platform-alerts | 1 hour |

### Useful Commands

```bash
# Silence alerts during maintenance
amtool silence add alertname=VigilNetHighErrorRate --duration=1h --comment="Deployment in progress"

# View active alerts
amtool alert --alertmanager.url=http://localhost:9093

# Test alert routing
amtool config routes test --config.file=alertmanager.yml severity=critical

# Check alert history
curl -s http://localhost:9090/api/v1/alerts | jq
```

---

**Document Control:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-02-15 | DevOps Team | Initial release |

**Review Schedule:** Monthly
