# VigilNet Rollback Procedures

**Version:** 1.0.0  
**Last Updated:** 2026-02-15  
**Status:** Production Ready  
**Classification:** Internal Use Only

---

## Table of Contents

1. [Overview](#overview)
2. [Rollback Triggers](#rollback-triggers)
3. [Quick Decision Matrix](#quick-decision-matrix)
4. [Docker Compose Rollback](#docker-compose-rollback)
5. [Kubernetes Rollback](#kubernetes-rollback)
6. [Database Rollback](#database-rollback)
7. [Configuration Rollback](#configuration-rollback)
8. [Emergency Procedures](#emergency-procedures)
9. [Post-Rollback Actions](#post-rollback-actions)
10. [Automation](#automation)

---

## Overview

This document defines standardized rollback procedures for VigilNet deployments. Rollbacks should be executed when:

- New deployments introduce critical bugs
- Performance degrades beyond acceptable thresholds
- Security vulnerabilities are discovered
- Data integrity issues occur
- Service availability is compromised

### Rollback Principles

1. **Safety First**: Always prioritize service stability
2. **Speed**: Rollbacks should complete within 5 minutes
3. **Verification**: Always verify rollback success
4. **Documentation**: Log all rollback actions
5. **Communication**: Notify stakeholders immediately

---

## Rollback Triggers

### Automatic Triggers (Immediate)

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Health Check Failures | > 80% for 2 minutes | Auto-rollback enabled |
| Error Rate Spike | > 20% for 3 minutes | Auto-rollback enabled |
| Complete Outage | 0% success for 1 minute | Auto-rollback enabled |
| Memory Exhaustion | OOMKilled events | Auto-rollback enabled |
| Security Breach | Confirmed compromise | Immediate manual rollback |

### Manual Triggers (Management Decision)

- Feature not working as expected (non-critical)
- Performance degradation (< 20% error rate)
- User complaints exceeding threshold
- Data inconsistency detected
- Dependency failures

---

## Quick Decision Matrix

```
┌─────────────────────────────────────────────────────────────────┐
│                    ROLLBACK DECISION TREE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Service Down?                                                   │
│       │                                                          │
│       ▼                                                          │
│   YES ────────► IMMEDIATE ROLLBACK (No approval needed)         │
│       │                                                          │
│       NO                                                         │
│       │                                                          │
│       ▼                                                          │
│  Error Rate > 20%?                                               │
│       │                                                          │
│       ▼                                                          │
│   YES ────────► EMERGENCY ROLLBACK (Notify after)               │
│       │                                                          │
│       NO                                                         │
│       │                                                          │
│       ▼                                                          │
│  Performance Degraded?                                           │
│       │                                                          │
│       ▼                                                          │
│   YES ────────► STANDARD ROLLBACK (Manager approval)            │
│       │                                                          │
│       NO                                                         │
│       │                                                          │
│       ▼                                                          │
│  Minor Issue? ────────► HOTFIX OR WAIT                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Approval Requirements

| Rollback Type | Approval Required | Notification | Time Limit |
|---------------|-------------------|--------------|------------|
| **Emergency** | No | Within 15 min | 5 minutes |
| **Standard** | Team Lead | Before + After | 15 minutes |
| **Planned** | Manager | 1 hour before | 30 minutes |

---

## Docker Compose Rollback

### Standard Rollback Procedure

```bash
#!/bin/bash
# rollback-docker-standard.sh

PREVIOUS_VERSION=${1:-"latest-stable"}
ENV_FILE=".env"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"

echo "========================================="
echo "VigilNet Docker Rollback"
echo "Target Version: $PREVIOUS_VERSION"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================="

# 1. Pre-rollback check
echo "[1/7] Running pre-rollback health check..."
if ./scripts/health-check.sh; then
    echo "✓ Current system is operational"
    CURRENT_STATE="healthy"
else
    echo "⚠ Current system is already degraded"
    CURRENT_STATE="degraded"
fi

# 2. Backup current state
echo "[2/7] Creating backup..."
BACKUP_DIR="/backups/rollback-$(date +%Y%m%d-%H%M%S)"
mkdir -p $BACKUP_DIR
docker-compose $COMPOSE_FILES config > $BACKUP_DIR/docker-compose.backup.yml
cp $ENV_FILE $BACKUP_DIR/.env.backup
echo "✓ Backup saved to $BACKUP_DIR"

# 3. Update version
echo "[3/7] Updating to version $PREVIOUS_VERSION..."
sed -i "s/VIGILNET_VERSION=.*/VIGILNET_VERSION=$PREVIOUS_VERSION/" $ENV_FILE

# 4. Pull previous image
echo "[4/7] Pulling images..."
docker-compose $COMPOSE_FILES pull

# 5. Stop and remove current containers
echo "[5/7] Stopping current deployment..."
docker-compose $COMPOSE_FILES down --remove-orphans

# 6. Start with previous version
echo "[6/7] Starting rollback deployment..."
docker-compose $COMPOSE_FILES up -d

# 7. Verify rollback
echo "[7/7] Verifying rollback..."
sleep 10
ATTEMPTS=0
MAX_ATTEMPTS=12

while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
    if ./scripts/health-check.sh; then
        echo "✓ Rollback successful!"
        echo "✓ Service is operational on version $PREVIOUS_VERSION"
        
        # Send success notification
        curl -X POST $SLACK_WEBHOOK_URL \
            -H 'Content-Type: application/json' \
            -d "{\"text\":\"✅ VigilNet rollback to $PREVIOUS_VERSION successful\"}"
        
        exit 0
    fi
    
    ATTEMPTS=$((ATTEMPTS + 1))
    echo "⏳ Health check failed, retrying ($ATTEMPTS/$MAX_ATTEMPTS)..."
    sleep 10
done

echo "✗ Rollback verification failed after $MAX_ATTEMPTS attempts"
echo "Manual intervention required"

# Attempt emergency restoration
if [ "$CURRENT_STATE" == "healthy" ]; then
    echo "Attempting to restore previous version..."
    cp $BACKUP_DIR/.env.backup $ENV_FILE
    docker-compose $COMPOSE_FILES up -d
fi

exit 1
```

### Emergency Rollback (One-Liner)

```bash
# Emergency rollback to previous version (no verification wait)
docker-compose down && \
sed -i 's/VIGILNET_VERSION=.*/VIGILNET_VERSION=latest-stable/' .env && \
docker-compose up -d && \
echo "Rollback initiated - verify with: docker-compose ps"
```

### Rollback Verification

```bash
#!/bin/bash
# verify-rollback.sh

echo "=== Rollback Verification ==="

# Check container status
if ! docker-compose ps | grep -q "Up"; then
    echo "✗ Containers not running"
    exit 1
fi

# Check version
CURRENT_VERSION=$(docker-compose exec -T vigilnet-node /app/vigilnet --version)
echo "Current version: $CURRENT_VERSION"

# Health check
if curl -sf http://localhost:5001/health > /dev/null; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed"
    exit 1
fi

# Check error rate
ERROR_RATE=$(curl -s http://localhost:8080/metrics | \
    grep "vigilnet_errors_total" | head -1 | awk '{print $2}')
if [ -n "$ERROR_RATE" ] && [ "$ERROR_RATE" -lt 100 ]; then
    echo "✓ Error rate acceptable: $ERROR_RATE"
else
    echo "⚠ Error rate high or unavailable"
fi

echo "=== Verification Complete ==="
```

---

## Kubernetes Rollback

### Standard Rollback Procedure

```bash
#!/bin/bash
# rollback-k8s-standard.sh

NAMESPACE="vigilnet"
DEPLOYMENT=${1:-"vigilnet-node"}
REVISION=${2:-"0"}  # 0 means previous revision

echo "========================================="
echo "VigilNet Kubernetes Rollback"
echo "Deployment: $DEPLOYMENT"
echo "Namespace: $NAMESPACE"
echo "Target Revision: $REVISION"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================="

# 1. Show current status
echo "[1/8] Current deployment status..."
kubectl get deployment/$DEPLOYMENT -n $NAMESPACE

# 2. Show rollout history
echo "[2/8] Available revisions..."
kubectl rollout history deployment/$DEPLOYMENT -n $NAMESPACE

# 3. Pre-rollback snapshot
echo "[3/8] Creating pre-rollback snapshot..."
kubectl get deployment/$DEPLOYMENT -n $NAMESPACE -o yaml > \
    /tmp/pre-rollback-$DEPLOYMENT-$(date +%Y%m%d-%H%M%S).yaml

# 4. Check current health
echo "[4/8] Checking current health..."
kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT

# 5. Execute rollback
echo "[5/8] Executing rollback to revision $REVISION..."
if [ "$REVISION" == "0" ]; then
    kubectl rollout undo deployment/$DEPLOYMENT -n $NAMESPACE
else
    kubectl rollout undo deployment/$DEPLOYMENT -n $NAMESPACE --to-revision=$REVISION
fi

# 6. Monitor rollout
echo "[6/8] Monitoring rollout..."
kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=300s

if [ $? -ne 0 ]; then
    echo "✗ Rollout failed to complete within timeout"
    echo "Checking pod status..."
    kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT
    kubectl describe pods -n $NAMESPACE -l app=$DEPLOYMENT
    exit 1
fi

# 7. Verify deployment
echo "[7/8] Verifying deployment..."
sleep 10

# Check pod readiness
READY_PODS=$(kubectl get deployment/$DEPLOYMENT -n $NAMESPACE \
    -o jsonpath='{.status.readyReplicas}')
DESIRED_PODS=$(kubectl get deployment/$DEPLOYMENT -n $NAMESPACE \
    -o jsonpath='{.spec.replicas}')

if [ "$READY_PODS" == "$DESIRED_PODS" ]; then
    echo "✓ All pods ready ($READY_PODS/$DESIRED_PODS)"
else
    echo "✗ Pod readiness mismatch ($READY_PODS/$DESIRED_PODS)"
    exit 1
fi

# 8. Post-rollback health check
echo "[8/8] Running health checks..."
POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT -o jsonpath='{.items[0].metadata.name}')

if kubectl exec -n $NAMESPACE $POD_NAME -- /app/health-check.sh; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed in pod"
    exit 1
fi

# Test service endpoint
if kubectl port-forward -n $NAMESPACE svc/$DEPLOYMENT 5001:5001 &
PF_PID=$!
sleep 2
if curl -sf http://localhost:5001/health; then
    echo "✓ Service endpoint healthy"
else
    echo "✗ Service endpoint unhealthy"
fi
kill $PF_PID 2>/dev/null

echo "========================================="
echo "✓ Rollback completed successfully!"
echo "Current revision:"
kubectl rollout history deployment/$DEPLOYMENT -n $NAMESPACE | tail -5
echo "========================================="
```

### Emergency Rollback (Fastest)

```bash
#!/bin/bash
# rollback-k8s-emergency.sh

NAMESPACE="vigilnet"
DEPLOYMENT="vigilnet-node"

echo "EMERGENCY ROLLBACK INITIATED"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Immediate rollback without confirmation
kubectl rollout undo deployment/$DEPLOYMENT -n $NAMESPACE

# Quick status check
echo "Rollback status:"
kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=180s

# Force redeploy if stuck
if [ $? -ne 0 ]; then
    echo "Rollout stuck, forcing restart..."
    kubectl rollout restart deployment/$DEPLOYMENT -n $NAMESPACE
fi

echo "Emergency rollback complete"
echo "Verify with: kubectl get pods -n $NAMESPACE"
```

### Blue-Green Rollback

```bash
#!/bin/bash
# rollback-blue-green.sh

NAMESPACE="vigilnet"
SERVICE="vigilnet"

echo "Blue-Green Rollback"
echo "==================="

# Get current active color
CURRENT_COLOR=$(kubectl get svc $SERVICE -n $NAMESPACE \
    -o jsonpath='{.spec.selector.color}')

if [ "$CURRENT_COLOR" == "blue" ]; then
    PREVIOUS_COLOR="green"
else
    PREVIOUS_COLOR="blue"
fi

echo "Current active color: $CURRENT_COLOR"
echo "Rolling back to: $PREVIOUS_COLOR"

# Scale up previous color if down
kubectl scale deployment/vigilnet-$PREVIOUS_COLOR --replicas=3 -n $NAMESPACE

# Wait for pods to be ready
echo "Waiting for $PREVIOUS_COLOR to be ready..."
kubectl wait --for=condition=available deployment/vigilnet-$PREVIOUS_COLOR \
    -n $NAMESPACE --timeout=300s

# Switch traffic
kubectl patch svc $SERVICE -n $NAMESPACE -p \
    "{\"spec\":{\"selector\":{\"color\":\"$PREVIOUS_COLOR\"}}}"

# Scale down current color (failed deployment)
kubectl scale deployment/vigilnet-$CURRENT_COLOR --replicas=0 -n $NAMESPACE

echo "✓ Rollback complete"
echo "Active color is now: $PREVIOUS_COLOR"
```

---

## Database Rollback

### Pre-Rollback Requirements

```bash
#!/bin/bash
# db-rollback-prereqs.sh

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file>"
    exit 1
fi

# Verify backup exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "✗ Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Verify backup integrity
echo "Verifying backup integrity..."
if ! vigilnet admin verify-backup --input $BACKUP_FILE; then
    echo "✗ Backup verification failed"
    exit 1
fi

echo "✓ Backup verified and ready for rollback"
```

### Database Rollback Procedure

```bash
#!/bin/bash
# rollback-database.sh

BACKUP_FILE=$1
NAMESPACE="vigilnet"

echo "========================================="
echo "VigilNet Database Rollback"
echo "Backup File: $BACKUP_FILE"
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================="

# 1. Scale down application
echo "[1/5] Scaling down application..."
kubectl scale deployment/vigilnet-node --replicas=0 -n $NAMESPACE
kubectl scale deployment/vigilnet-agent --replicas=0 -n $NAMESPACE

# Wait for scale down
sleep 10

# 2. Verify no active connections
echo "[2/5] Verifying no active connections..."
ACTIVE_CONNECTIONS=$(vigilnet admin db-connections | wc -l)
if [ "$ACTIVE_CONNECTIONS" -gt 0 ]; then
    echo "⚠ Warning: $ACTIVE_CONNECTIONS active connections"
    echo "Force closing connections..."
    vigilnet admin db-disconnect-all
fi

# 3. Restore from backup
echo "[3/5] Restoring from backup..."
vigilnet admin restore --input $BACKUP_FILE --force

if [ $? -ne 0 ]; then
    echo "✗ Database restore failed"
    echo "Manual intervention required"
    exit 1
fi

# 4. Verify database integrity
echo "[4/5] Verifying database integrity..."
vigilnet admin db-check

if [ $? -ne 0 ]; then
    echo "✗ Database integrity check failed"
    exit 1
fi

# 5. Scale up application
echo "[5/5] Scaling up application..."
kubectl scale deployment/vigilnet-node --replicas=3 -n $NAMESPACE
kubectl scale deployment/vigilnet-agent --replicas=3 -n $NAMESPACE

# Wait for pods
sleep 30

# Verify health
if kubectl exec -n $NAMESPACE deployment/vigilnet-node -- /app/health-check.sh; then
    echo "✓ Database rollback successful"
else
    echo "✗ Post-restore health check failed"
    exit 1
fi
```

---

## Configuration Rollback

### ConfigMap Rollback

```bash
#!/bin/bash
# rollback-config.sh

NAMESPACE="vigilnet"
CONFIGMAP="vigilnet-config"

echo "ConfigMap Rollback"
echo "=================="

# List previous versions
echo "Available ConfigMap versions:"
kubectl get configmap $CONFIGMAP -n $NAMESPACE -o yaml | \
    grep -A 5 "resourceVersion"

# Get previous version (requires versioned configs or backup)
PREVIOUS_CONFIG="/backups/config-$(date -d '1 day ago' +%Y%m%d).yaml"

if [ ! -f "$PREVIOUS_CONFIG" ]; then
    echo "Previous config backup not found"
    echo "Available backups:"
    ls -la /backups/config-*.yaml 2>/dev/null || echo "No backups found"
    exit 1
fi

# Apply previous config
echo "Applying previous configuration..."
kubectl apply -f $PREVIOUS_CONFIG -n $NAMESPACE

# Restart pods to pick up new config
echo "Restarting pods..."
kubectl rollout restart deployment/vigilnet-node -n $NAMESPACE

# Wait for restart
kubectl rollout status deployment/vigilnet-node -n $NAMESPACE

echo "✓ Configuration rollback complete"
```

### Secret Rollback

```bash
#!/bin/bash
# rollback-secrets.sh

NAMESPACE="vigilnet"
SECRET_NAME="vigilnet-secrets"

echo "Secret Rollback"
echo "==============="

# WARNING: Secrets should be versioned in a secure vault
# This example assumes HashiCorp Vault or similar

# Restore previous version from vault
vault kv get -version=-1 secret/vigilnet/production > /tmp/previous-secrets.json

# Create secret from restored data
kubectl create secret generic $SECRET_NAME \
    --from-file=/tmp/previous-secrets.json \
    -n $NAMESPACE \
    --dry-run=client -o yaml | kubectl apply -f -

# Restart affected pods
kubectl rollout restart deployment/vigilnet-node -n $NAMESPACE

echo "✓ Secret rollback complete"
```

---

## Emergency Procedures

### Complete Service Failure Recovery

```bash
#!/bin/bash
# emergency-full-recovery.sh

NAMESPACE="vigilnet"
STABLE_VERSION="1.0.0"

echo "🚨 EMERGENCY FULL RECOVERY 🚨"
echo "=============================="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# 1. Immediate scale down of all services
echo "[1/8] Emergency shutdown of all services..."
kubectl scale deployment --all --replicas=0 -n $NAMESPACE
kubectl delete pods --all -n $NAMESPACE --force --grace-period=0 2>/dev/null

# 2. Clear any stuck resources
echo "[2/8] Clearing stuck resources..."
kubectl delete pods --all -n $NAMESPACE --force --grace-period=0 2>/dev/null || true

# 3. Verify clean state
echo "[3/8] Verifying clean state..."
sleep 5
RUNNING_PODS=$(kubectl get pods -n $NAMESPACE --no-headers | wc -l)
if [ "$RUNNING_PODS" -gt 0 ]; then
    echo "⚠ Warning: $RUNNING_PODS pods still present"
fi

# 4. Reset to stable image version
echo "[4/8] Resetting to stable version $STABLE_VERSION..."
kubectl set image deployment/vigilnet-node \
    vigilnet=vigilnet/vigilnet:$STABLE_VERSION \
    -n $NAMESPACE

kubectl set image deployment/vigilnet-agent \
    vigilnet=vigilnet/vigilnet:$STABLE_VERSION \
    -n $NAMESPACE

# 5. Scale up minimum viable capacity
echo "[5/8] Scaling to minimum viable capacity..."
kubectl scale deployment/vigilnet-node --replicas=1 -n $NAMESPACE

# 6. Verify single pod health
echo "[6/8] Verifying single pod health..."
sleep 30

POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=vigilnet-node \
    -o jsonpath='{.items[0].metadata.name}')

if ! kubectl exec -n $NAMESPACE $POD_NAME -- /app/health-check.sh; then
    echo "✗ Single pod health check failed"
    echo "Getting logs for diagnosis..."
    kubectl logs -n $NAMESPACE $POD_NAME --tail=100
    exit 1
fi

echo "✓ Single pod healthy"

# 7. Scale to full capacity
echo "[7/8] Scaling to full capacity..."
kubectl scale deployment/vigilnet-node --replicas=3 -n $NAMESPACE
kubectl scale deployment/vigilnet-agent --replicas=3 -n $NAMESPACE

# 8. Final verification
echo "[8/8] Final verification..."
sleep 30

if ./scripts/health-check.sh; then
    echo ""
    echo "✅ EMERGENCY RECOVERY SUCCESSFUL"
    echo "Service restored to version $STABLE_VERSION"
    echo "All systems operational"
else
    echo ""
    echo "❌ EMERGENCY RECOVERY INCOMPLETE"
    echo "Manual intervention required"
    exit 1
fi
```

### Multi-Region Failover

```bash
#!/bin/bash
# multi-region-failover.sh

PRIMARY_REGION="us-east-1"
FAILOVER_REGION="us-west-2"
NAMESPACE="vigilnet"

echo "Multi-Region Failover"
echo "====================="
echo "Primary: $PRIMARY_REGION"
echo "Failover: $FAILOVER_REGION"
echo ""

# 1. Switch DNS to failover region
echo "[1/4] Switching DNS to failover region..."
aws route53 change-resource-record-sets \
    --hosted-zone-id $ZONE_ID \
    --change-batch file://dns-failover-$FAILOVER_REGION.json

# 2. Scale up failover region
echo "[2/4] Scaling up failover region..."
kubectl --context=$FAILOVER_REGION \
    scale deployment/vigilnet-node --replicas=3 -n $NAMESPACE

# 3. Verify failover region health
echo "[3/4] Verifying failover region..."
sleep 30
kubectl --context=$FAILOVER_REGION \
    rollout status deployment/vigilnet-node -n $NAMESPACE

# 4. Scale down primary region (after confirming failover works)
echo "[4/4] Scaling down primary region..."
kubectl --context=$PRIMARY_REGION \
    scale deployment/vigilnet-node --replicas=0 -n $NAMESPACE

echo "✓ Failover to $FAILOVER_REGION complete"
echo "Primary region $PRIMARY_REGION scaled down for investigation"
```

---

## Post-Rollback Actions

### Mandatory Checklist

```bash
#!/bin/bash
# post-rollback-checklist.sh

echo "Post-Rollback Checklist"
echo "======================="

CHECKLIST=(
    "Verify all pods are Running: kubectl get pods -n vigilnet"
    "Verify service endpoints: kubectl get endpoints -n vigilnet"
    "Test API health: curl http://localhost:5001/health"
    "Check error rates: curl http://localhost:8080/metrics | grep errors"
    "Verify logs show normal operation: kubectl logs -n vigilnet --tail=50"
    "Test critical user journeys: ./scripts/smoke-tests.sh"
    "Verify monitoring/alerts working: curl http://localhost:9090/-/healthy"
    "Update incident documentation: Create incident report"
    "Notify stakeholders: Send status update"
    "Schedule post-mortem: Create calendar event"
)

for item in "${CHECKLIST[@]}"; do
    echo "□ $item"
done

echo ""
echo "All items must be checked before considering rollback complete"
```

### Incident Documentation Template

```markdown
# Rollback Incident Report

## Metadata
- **Incident ID**: ROLLBACK-YYYYMMDD-XXX
- **Date/Time**: YYYY-MM-DD HH:MM UTC
- **Duration**: XX minutes
- **Severity**: P1/P2/P3

## Trigger
- **Detection Method**: Automatic/Manual
- **Trigger Condition**: [Describe what triggered the rollback]

## Impact
- **Services Affected**: [List affected services]
- **Users Affected**: [Number/percentage]
- **Data Loss**: Yes/No (details if yes)

## Rollback Execution
- **Rollback Type**: Docker/Kubernetes/Database/Config
- **Target Version**: [Version rolled back to]
- **Previous Version**: [Version rolled back from]
- **Execution Time**: XX minutes
- **Verification Status**: Success/Partial/Failed

## Root Cause (Preliminary)
[Describe what went wrong]

## Actions Taken
1. [Step 1]
2. [Step 2]
...

## Follow-up Actions
- [ ] Fix underlying issue
- [ ] Update monitoring thresholds
- [ ] Improve testing
- [ ] Update runbook

## Lessons Learned
[What can we learn from this incident]

## Timeline
- XX:XX - Issue detected
- XX:XX - Rollback initiated
- XX:XX - Rollback completed
- XX:XX - Service verified
```

---

## Automation

### GitHub Actions Auto-Rollback

```yaml
# .github/workflows/rollback.yml
name: Auto Rollback

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to rollback'
        required: true
        default: 'staging'
        type: choice
        options:
          - staging
          - production
      target_version:
        description: 'Version to rollback to (leave empty for previous)'
        required: false
        type: string

jobs:
  rollback:
    runs-on: ubuntu-latest
    environment: ${{ github.event.inputs.environment }}
    steps:
      - uses: actions/checkout@v4

      - name: Setup kubectl
        uses: azure/setup-kubectl@v3

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Update kubeconfig
        run: |
          aws eks update-kubeconfig \
            --name vigilnet-${{ github.event.inputs.environment }}

      - name: Execute rollback
        run: |
          if [ -n "${{ github.event.inputs.target_version }}" ]; then
            ./scripts/rollback-k8s.sh vigilnet-node 0
          else
            ./scripts/rollback-k8s.sh vigilnet-node \
              ${{ github.event.inputs.target_version }}
          fi

      - name: Verify rollback
        run: |
          kubectl rollout status deployment/vigilnet-node -n vigilnet
          ./scripts/health-check.sh

      - name: Notify team
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "🔄 Rollback to ${{ github.event.inputs.target_version }} completed for ${{ github.event.inputs.environment }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Automated Health Check with Auto-Rollback

```bash
#!/bin/bash
# auto-rollback-monitor.sh

NAMESPACE="vigilnet"
DEPLOYMENT="vigilnet-node"
ERROR_THRESHOLD=20  # Percentage
LATENCY_THRESHOLD=5000  # Milliseconds

echo "Auto-Rollback Monitor"
echo "===================="
echo "Error Threshold: ${ERROR_THRESHOLD}%"
echo "Latency Threshold: ${LATENCY_THRESHOLD}ms"
echo ""

while true; do
    # Get current error rate
    ERROR_RATE=$(curl -s http://localhost:8080/metrics | \
        grep "vigilnet_errors_total" | head -1 | awk '{print $2}')
    
    # Get current latency
    LATENCY=$(curl -s http://localhost:8080/metrics | \
        grep "vigilnet_request_duration_seconds" | \
        grep "quantile=\"0.95\"" | awk '{print $2 * 1000}')
    
    echo "Current - Error Rate: ${ERROR_RATE}%, Latency: ${LATENCY}ms"
    
    # Check if rollback needed
    if [ "${ERROR_RATE%.*}" -gt "$ERROR_THRESHOLD" ] || \
       [ "${LATENCY%.*}" -gt "$LATENCY_THRESHOLD" ]; then
        echo "⚠️ THRESHOLD EXCEEDED - Initiating auto-rollback"
        
        # Trigger rollback
        ./scripts/rollback-k8s-emergency.sh
        
        # Send alert
        curl -X POST $SLACK_WEBHOOK_URL \
            -H 'Content-Type: application/json' \
            -d "{\"text\":\"🚨 Auto-rollback triggered due to threshold breach. Error: ${ERROR_RATE}%, Latency: ${LATENCY}ms\"}"
        
        exit 0
    fi
    
    sleep 30
done
```

---

## Appendix

### Rollback Decision Log Template

```
┌─────────────────────────────────────────────────────────────┐
│ ROLLBACK DECISION LOG                                       │
├─────────────────────────────────────────────────────────────┤
│ Timestamp: _______________ UTC                              │
│ Operator: ___________________________                       │
│ Incident ID: _______________________                        │
├─────────────────────────────────────────────────────────────┤
│ REASON FOR ROLLBACK:                                        │
│ □ Service unavailable        □ High error rate              │
│ □ Performance degradation    □ Security issue               │
│ □ Data corruption            □ Configuration error          │
│ □ Other: ___________________                                │
├─────────────────────────────────────────────────────────────┤
│ ROLLBACK TYPE:                                              │
│ □ Docker Compose             □ Kubernetes                   │
│ □ Database                   □ Configuration                │
│ □ Emergency Full Recovery    □ Multi-region Failover        │
├─────────────────────────────────────────────────────────────┤
│ ROLLBACK TARGET:                                            │
│ Previous Version: _________________                         │
│ Current Version: __________________                         │
├─────────────────────────────────────────────────────────────┤
│ RESULT:                                                     │
│ □ Success                    □ Partial                      │
│ □ Failed                     □ Escalated                    │
├─────────────────────────────────────────────────────────────┤
│ NOTES:                                                      │
│ _____________________________________________               │
│ _____________________________________________               │
└─────────────────────────────────────────────────────────────┘
```

### Contact Information

| Role | Contact | When to Contact |
|------|---------|-----------------|
| On-Call Engineer | PagerDuty | All P1/P2 rollbacks |
| DevOps Lead | Slack: @devops-lead | Failed rollbacks |
| Engineering Manager | eng-mgr@vigilnet.io | Customer-impacting issues |
| Security Team | security@vigilnet.io | Security-related rollbacks |

---

**Document Control:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-02-15 | DevOps Team | Initial release |

**Review Schedule:** After each rollback event
