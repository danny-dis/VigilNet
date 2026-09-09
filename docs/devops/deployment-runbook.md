# VigilNet Deployment Runbook

**Version:** 1.0.0  
**Last Updated:** 2026-02-15  
**Owner:** DevOps Team  
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Deployment Procedures](#deployment-procedures)
5. [Health Checks](#health-checks)
6. [Monitoring Setup](#monitoring-setup)
7. [Incident Response](#incident-response)
8. [Rollback Procedures](#rollback-procedures)

---

## Overview

This runbook provides step-by-step instructions for deploying VigilNet components in production environments. It covers:

- Core node deployment
- Agent network setup
- Monitoring configuration
- Incident response procedures

### Deployment Environments

| Environment | Purpose | Branch | Auto-Deploy |
|-------------|---------|--------|-------------|
| Development | Local testing | `feature/*` | No |
| Staging | Integration testing | `develop` | Yes |
| Production | Live services | `main` | Manual |

---

## Prerequisites

### System Requirements

#### Minimum Hardware (Per Node)

```yaml
CPU: 4 cores (x86_64 or ARM64)
Memory: 8 GB RAM
Storage: 100 GB SSD
Network: 1 Gbps
OS: Ubuntu 22.04 LTS / Debian 12 / RHEL 9
```

#### Recommended Hardware (Production)

```yaml
CPU: 8+ cores
Memory: 16+ GB RAM
Storage: 500 GB NVMe SSD
Network: 10 Gbps
OS: Ubuntu 24.04 LTS
```

### Software Requirements

```bash
# Core dependencies
sudo apt-get update && sudo apt-get install -y \
    docker-ce \
    docker-compose-plugin \
    kubectl \
    helm \
    jq \
    curl \
    wget \
    openssl \
    libssl-dev \
    pkg-config

# Rust toolchain (for source builds)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installations
docker --version
kubectl version --client
helm version
rustc --version
```

### Network Requirements

| Port | Protocol | Service | Direction | Description |
|------|----------|---------|-----------|-------------|
| 4001 | TCP/UDP | libp2p | Inbound | P2P communication |
| 5001 | TCP | API | Inbound | HTTP API |
| 8080 | TCP | Metrics | Internal | Prometheus metrics |
| 9090 | TCP | Prometheus | Internal | Monitoring |
| 9093 | TCP | Alertmanager | Internal | Alerting |
| 9100 | TCP | Node Exporter | Internal | System metrics |

---

## Pre-Deployment Checklist

### 1. Environment Validation

```bash
# Verify Docker daemon
docker info

# Check disk space
df -h

# Verify network connectivity
ping -c 4 8.8.8.8

# Check firewall rules
sudo ufw status
# or
sudo iptables -L
```

### 2. Secret Management

Ensure all required secrets are available in your secret store:

```bash
# Required secrets checklist
# [ ] VIGILNET_NODE_KEY - Ed25519 private key
# [ ] VIGILNET_AGENT_TOKEN - Agent authentication token
# [ ] TLS_CERT - Server certificate
# [ ] TLS_KEY - Server private key
# [ ] PROMETHEUS_PASSWORD - Monitoring auth
# [ ] SLACK_WEBHOOK_URL - Alert notifications
```

### 3. Backup Current State

```bash
# Backup configuration
tar czf vigilnet-backup-$(date +%Y%m%d).tar.gz \
    /etc/vigilnet/ \
    /var/lib/vigilnet/ \
    ~/.config/vigilnet/

# Backup database (if applicable)
vigilnet admin backup --output /backups/vigilnet-$(date +%Y%m%d).db

# Verify backup
ls -lh /backups/vigilnet-*.db
```

### 4. Health Check Baseline

```bash
# Document current metrics
kubectl top nodes
kubectl top pods -n vigilnet

# Save current pod status
kubectl get pods -n vigilnet -o yaml > /tmp/pre-deploy-pods.yaml
```

---

## Deployment Procedures

### Standard Deployment (Docker Compose)

#### Step 1: Prepare Deployment Directory

```bash
mkdir -p /opt/vigilnet
cd /opt/vigilnet

# Download compose files
curl -O https://raw.githubusercontent.com/danny-dis/vigilnet/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/danny-dis/vigilnet/main/docker-compose.prod.yml
```

#### Step 2: Configure Environment

```bash
# Create environment file
cat > .env << 'EOF'
# VigilNet Configuration
VIGILNET_VERSION=1.0.0
VIGILNET_ENV=production
VIGILNET_LOG_LEVEL=info

# Network Configuration
VIGILNET_P2P_PORT=4001
VIGILNET_API_PORT=5001
VIGILNET_METRICS_PORT=8080

# Security
VIGILNET_ENABLE_E2EE=true
VIGILNET_REQUIRE_AUTH=true

# Bootstrap nodes (comma-separated)
VIGILNET_BOOTSTRAP_PEERS=/dns4/bootstrap1.vigilnet.io/tcp/4001/p2p/12D3KooW...

# Resource Limits
VIGILNET_MAX_CONNECTIONS=1000
VIGILNET_MAX_MEMORY_MB=4096
VIGILNET_MAX_CPU_CORES=4

# Monitoring
PROMETHEUS_RETENTION=15d
GRAFANA_ADMIN_PASSWORD=changeme
EOF

# Secure environment file
chmod 600 .env
```

#### Step 3: Deploy Services

```bash
# Pull latest images
docker-compose -f docker-compose.yml -f docker-compose.prod.yml pull

# Deploy with zero downtime
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose ps
```

#### Step 4: Verify Deployment

```bash
# Check service health
docker-compose ps

# View logs
docker-compose logs -f --tail=100

# Test API health
curl -s http://localhost:5001/health | jq
```

### Kubernetes Deployment

#### Step 1: Prepare Kubernetes Resources

```bash
# Create namespace
kubectl create namespace vigilnet --dry-run=client -o yaml | kubectl apply -f -

# Create secrets
kubectl create secret generic vigilnet-secrets \
  --from-literal=node-key="$VIGILNET_NODE_KEY" \
  --from-literal=agent-token="$VIGILNET_AGENT_TOKEN" \
  --namespace=vigilnet

# Create TLS secret
kubectl create secret tls vigilnet-tls \
  --cert=tls.crt \
  --key=tls.key \
  --namespace=vigilnet
```

#### Step 2: Deploy Helm Chart

```bash
# Add VigilNet Helm repo (if available)
helm repo add vigilnet https://charts.vigilnet.io
helm repo update

# Deploy with custom values
helm upgrade --install vigilnet vigilnet/vigilnet \
  --namespace vigilnet \
  --values values-production.yaml \
  --set image.tag=$VERSION \
  --wait \
  --timeout 10m

# Alternative: Deploy from local chart
helm upgrade --install vigilnet ./helm/vigilnet \
  --namespace vigilnet \
  --values values-production.yaml \
  --wait
```

#### Step 3: Verify Kubernetes Deployment

```bash
# Check pod status
kubectl get pods -n vigilnet -o wide

# Check services
kubectl get svc -n vigilnet

# Check ingress
kubectl get ingress -n vigilnet

# View pod logs
kubectl logs -n vigilnet -l app=vigilnet-node --tail=100 -f
```

### Blue-Green Deployment

For zero-downtime deployments:

```bash
#!/bin/bash
# blue-green-deploy.sh

VERSION=$1
NAMESPACE="vigilnet"
CURRENT_COLOR=$(kubectl get svc vigilnet -n $NAMESPACE -o jsonpath='{.spec.selector.color}')

if [ "$CURRENT_COLOR" == "blue" ]; then
    NEW_COLOR="green"
else
    NEW_COLOR="blue"
fi

echo "Current color: $CURRENT_COLOR"
echo "Deploying to: $NEW_COLOR"

# Deploy new version
kubectl set image deployment/vigilnet-$NEW_COLOR \
    vigilnet=vigilnet/vigilnet:$VERSION \
    -n $NAMESPACE

# Wait for rollout
kubectl rollout status deployment/vigilnet-$NEW_COLOR -n $NAMESPACE

# Run smoke tests
./scripts/smoke-tests.sh $NEW_COLOR

# Switch traffic
kubectl patch svc vigilnet -n $NAMESPACE -p \
    '{"spec":{"selector":{"color":"'$NEW_COLOR'"}}}'

# Scale down old version
kubectl scale deployment/vigilnet-$CURRENT_COLOR --replicas=0 -n $NAMESPACE

echo "Deployment complete. Active color: $NEW_COLOR"
```

---

## Health Checks

### Automated Health Checks

```bash
#!/bin/bash
# health-check.sh

VIGILNET_HOST="${VIGILNET_HOST:-localhost}"
VIGILNET_PORT="${VIGILNET_PORT:-5001}"
TIMEOUT=10

echo "=== VigilNet Health Check ==="
echo "Host: $VIGILNET_HOST:$VIGILNET_PORT"
echo "Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# 1. API Health
echo "1. Checking API health..."
API_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time $TIMEOUT \
    http://$VIGILNET_HOST:$VIGILNET_PORT/health)

if [ "$API_HEALTH" == "200" ]; then
    echo "   ✓ API health check passed"
else
    echo "   ✗ API health check failed (HTTP $API_HEALTH)"
    exit 1
fi

# 2. P2P Connectivity
echo "2. Checking P2P connectivity..."
PEER_COUNT=$(curl -s --max-time $TIMEOUT \
    http://$VIGILNET_HOST:$VIGILNET_PORT/api/v1/network/peers | jq '.count')

if [ "$PEER_COUNT" -gt 0 ]; then
    echo "   ✓ Connected to $PEER_COUNT peers"
else
    echo "   ⚠ No peers connected (may be normal for new nodes)"
fi

# 3. Metrics Endpoint
echo "3. Checking metrics endpoint..."
METRICS_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time $TIMEOUT \
    http://$VIGILNET_HOST:8080/metrics)

if [ "$METRICS_HEALTH" == "200" ]; then
    echo "   ✓ Metrics endpoint accessible"
else
    echo "   ✗ Metrics endpoint failed (HTTP $METRICS_HEALTH)"
fi

# 4. Disk Space
echo "4. Checking disk space..."
DISK_USAGE=$(df /var/lib/vigilnet | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -lt 80 ]; then
    echo "   ✓ Disk usage at ${DISK_USAGE}%"
else
    echo "   ✗ Disk usage critical at ${DISK_USAGE}%"
    exit 1
fi

# 5. Memory Usage
echo "5. Checking memory usage..."
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
if [ "$MEMORY_USAGE" -lt 90 ]; then
    echo "   ✓ Memory usage at ${MEMORY_USAGE}%"
else
    echo "   ⚠ Memory usage high at ${MEMORY_USAGE}%"
fi

echo ""
echo "=== Health Check Complete ==="
```

### Manual Verification Steps

#### 1. Service Status

```bash
# Check all services are running
docker-compose ps

# Or for Kubernetes
kubectl get pods -n vigilnet

# Expected output:
# NAME                             READY   STATUS    RESTARTS   AGE
# vigilnet-node-7d9f4b8c5-x2k9p   2/2     Running   0          5m
# vigilnet-agent-5c8d2a1b9-y4m7n  2/2     Running   0          5m
```

#### 2. Log Verification

```bash
# Check for errors
docker-compose logs --tail=100 | grep -i error

# Check for warnings
docker-compose logs --tail=100 | grep -i warn

# Verify successful startup
docker-compose logs --tail=50 | grep "VigilNet node started successfully"
```

#### 3. Network Connectivity

```bash
# Test P2P port connectivity
nc -zv localhost 4001

# Test API endpoints
curl -s http://localhost:5001/health | jq

# Test WebSocket (if enabled)
wscat -c ws://localhost:5001/ws
```

#### 4. Data Integrity

```bash
# Verify database connectivity
vigilnet admin db-check

# Check agent registry
vigilnet agent list

# Verify circle integrity
vigilnet circle list --verify
```

---

## Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'vigilnet-prod'
    replica: '{{.ExternalURL}}'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

rule_files:
  - '/etc/prometheus/alerts.yml'

scrape_configs:
  - job_name: 'vigilnet-nodes'
    static_configs:
      - targets: ['vigilnet-node:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s
    scrape_timeout: 5s

  - job_name: 'vigilnet-agents'
    static_configs:
      - targets: ['vigilnet-agent:8080']
    metrics_path: '/metrics'

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

### Grafana Dashboard

Access Grafana at `https://monitoring.vigilnet.io`

Default dashboards:
- **VigilNet Overview** (ID: 10001) - System health and performance
- **Agent Network** (ID: 10002) - Agent metrics and communication
- **P2P Network** (ID: 10003) - Peer connectivity and routing
- **Security Events** (ID: 10004) - Authentication and encryption metrics

### Alertmanager Configuration

```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@vigilnet.io'
  smtp_auth_username: 'alerts@vigilnet.io'
  smtp_auth_password: '{{ .Env.SMTP_PASSWORD }}'

route:
  receiver: 'default'
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      continue: true
    - match:
        severity: warning
      receiver: 'slack-warnings'

receivers:
  - name: 'default'
    slack_configs:
      - api_url: '{{ .Env.SLACK_WEBHOOK_URL }}'
        channel: '#alerts'
        title: 'VigilNet Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: '{{ .Env.PAGERDUTY_KEY }}'
        severity: critical

  - name: 'slack-warnings'
    slack_configs:
      - api_url: '{{ .Env.SLACK_WEBHOOK_URL }}'
        channel: '#warnings'
        title: 'VigilNet Warning'

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']
```

---

## Incident Response

### Incident Severity Levels

| Level | Description | Response Time | Escalation |
|-------|-------------|---------------|------------|
| P1 - Critical | Service completely unavailable | 15 minutes | Page on-call + leadership |
| P2 - High | Major functionality impaired | 1 hour | Page on-call |
| P3 - Medium | Minor functionality impaired | 4 hours | Ticket assigned |
| P4 - Low | Cosmetic issues, non-urgent | 24 hours | Backlog |

### Incident Response Playbook

#### P1 - Complete Service Outage

```bash
#!/bin/bash
# incident-response-p1.sh

INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
echo "=== INCIDENT $INCIDENT_ID ==="

# 1. Immediate Assessment
echo "1. Assessing service status..."
kubectl get pods -n vigilnet
kubectl get svc -n vigilnet

# 2. Check for recent changes
echo "2. Recent deployments..."
kubectl rollout history deployment/vigilnet-node -n vigilnet

# 3. Check resource exhaustion
echo "3. Resource usage..."
kubectl top nodes
kubectl top pods -n vigilnet

# 4. Gather logs
echo "4. Collecting logs..."
kubectl logs -n vigilnet -l app=vigilnet-node --tail=1000 > /tmp/incident-$INCIDENT_ID.log

# 5. Quick mitigation - Scale up if needed
echo "5. Attempting mitigation..."
kubectl scale deployment/vigilnet-node --replicas=5 -n vigilnet

# 6. If still failing, initiate rollback
echo "6. Rollback if needed..."
# kubectl rollout undo deployment/vigilnet-node -n vigilnet

echo "=== Incident $INCIDENT_ID response complete ==="
echo "Logs saved to: /tmp/incident-$INCIDENT_ID.log"
```

#### P2 - High Latency or Errors

```bash
#!/bin/bash
# incident-response-p2.sh

echo "=== P2 Incident Response ==="

# 1. Check error rates
curl -s http://localhost:8080/metrics | grep vigilnet_errors_total

# 2. Check latency
curl -s http://localhost:8080/metrics | grep vigilnet_request_duration_seconds

# 3. Restart affected pods
kubectl rollout restart deployment/vigilnet-node -n vigilnet

# 4. Monitor recovery
watch -n 5 'curl -s http://localhost:5001/health'
```

### Communication Templates

#### P1 Notification (Slack)

```
🚨 **INCIDENT ALERT - P1** 🚨

**Service:** VigilNet Production
**Status:** CRITICAL OUTAGE
**Started:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Impact:** Complete service unavailability

**Symptoms:**
- Health checks failing
- Error rate > 90%
- P2P connections dropped

**Actions:**
- On-call engineer paged
- War room initiated
- Investigation in progress

**Updates:** Every 15 minutes in #incidents

Incident ID: INC-YYYYMMDD-HHMMSS
```

#### Status Page Update

```
[Investigating] VigilNet Service Disruption

We are currently investigating reports of service disruption affecting 
the VigilNet network. Users may experience connection issues.

Our engineering team is actively working on a resolution. We will provide 
updates every 30 minutes.

Posted: $(date -u +%Y-%m-%dT%H:%M:%SZ)
```

---

## Rollback Procedures

### Automatic Rollback Triggers

The following conditions automatically trigger a rollback:

1. **Health check failures** for > 5 minutes
2. **Error rate** > 10% for > 3 minutes
3. **Latency** > 10 seconds for > 2 minutes
4. **Memory usage** > 95% for > 5 minutes
5. **Manual rollback** initiated via command

### Rollback Commands

#### Docker Compose Rollback

```bash
#!/bin/bash
# rollback-docker.sh

PREVIOUS_VERSION=$1

echo "=== Rolling back to version $PREVIOUS_VERSION ==="

# 1. Update docker-compose to previous version
sed -i "s/vigilnet:.*/vigilnet:$PREVIOUS_VERSION/" docker-compose.yml

# 2. Pull previous image
docker-compose pull

# 3. Stop current containers
docker-compose down

# 4. Start with previous version
docker-compose up -d

# 5. Verify rollback
sleep 10
./health-check.sh

echo "=== Rollback complete ==="
```

#### Kubernetes Rollback

```bash
#!/bin/bash
# rollback-k8s.sh

NAMESPACE="vigilnet"
DEPLOYMENT="vigilnet-node"

echo "=== Kubernetes Rollback ==="

# 1. View rollout history
echo "Available revisions:"
kubectl rollout history deployment/$DEPLOYMENT -n $NAMESPACE

# 2. Perform rollback
echo "Rolling back to previous revision..."
kubectl rollout undo deployment/$DEPLOYMENT -n $NAMESPACE

# 3. Monitor rollback progress
echo "Monitoring rollback..."
kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE

# 4. Verify rollback
echo "Verifying deployment..."
kubectl get pods -n $NAMESPACE

# 5. Test health
echo "Running health checks..."
sleep 30
kubectl exec -n $NAMESPACE deployment/$DEPLOYMENT -- /app/health-check.sh

echo "=== Rollback complete ==="
```

#### Database Rollback (if applicable)

```bash
#!/bin/bash
# rollback-database.sh

BACKUP_FILE=$1

echo "=== Database Rollback ==="
echo "Restoring from: $BACKUP_FILE"

# 1. Stop application
kubectl scale deployment/vigilnet-node --replicas=0 -n vigilnet

# 2. Restore database
vigilnet admin restore --input $BACKUP_FILE

# 3. Verify restore
vigilnet admin db-check

# 4. Restart application
kubectl scale deployment/vigilnet-node --replicas=3 -n vigilnet

# 5. Verify health
sleep 30
./health-check.sh

echo "=== Database rollback complete ==="
```

### Post-Rollback Checklist

```bash
#!/bin/bash
# post-rollback-checklist.sh

echo "=== Post-Rollback Checklist ==="

echo "□ Verify all pods are Running"
kubectl get pods -n vigilnet

echo "□ Check service endpoints"
kubectl get endpoints -n vigilnet

echo "□ Verify ingress rules"
kubectl get ingress -n vigilnet

echo "□ Test API health"
curl -s http://localhost:5001/health | jq

echo "□ Check error rates"
curl -s http://localhost:8080/metrics | grep vigilnet_errors_total

echo "□ Verify metrics collection"
curl -s http://localhost:9090/api/v1/status/targets | jq

echo "□ Test critical user journeys"
./scripts/smoke-tests.sh

echo "□ Update incident documentation"
echo "□ Schedule post-mortem"
echo "□ Review and update runbook if needed"

echo "=== Checklist Complete ==="
```

---

## Appendix

### A. Useful Commands Reference

```bash
# View all logs
kubectl logs -n vigilnet -l app=vigilnet-node --tail=1000 -f

# Execute shell in pod
kubectl exec -it -n vigilnet deployment/vigilnet-node -- /bin/sh

# Port forward for local testing
kubectl port-forward -n vigilnet svc/vigilnet 5001:5001

# Resource usage
kubectl top pods -n vigilnet
kubectl top nodes

# Events
kubectl get events -n vigilnet --sort-by='.lastTimestamp'

# Network policy test
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- /bin/bash
```

### B. Contact Information

| Role | Name | Contact | Escalation |
|------|------|---------|------------|
| On-Call Engineer | Rotating | pagerduty.com | +1 hour |
| DevOps Lead | TBD | devops@vigilnet.io | Immediate |
| Engineering Manager | TBD | eng-mgr@vigilnet.io | P1 only |
| Security Team | TBD | security@vigilnet.io | Security issues |

### C. Related Documentation

- [Architecture Overview](./architecture.md)
- [Security Hardening Guide](./security.md)
- [Troubleshooting Guide](./troubleshooting.md)
- [API Documentation](./api.md)

---

**Document Control:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-02-15 | DevOps Team | Initial release |

**Review Schedule:** Quarterly
