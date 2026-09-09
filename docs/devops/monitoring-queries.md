# VigilNet Monitoring Dashboard Queries

This document contains Prometheus PromQL queries for monitoring VigilNet infrastructure and services.

## Table of Contents

1. [Overview Dashboard](#overview-dashboard)
2. [Agent Network Dashboard](#agent-network-dashboard)
3. [P2P Network Dashboard](#p2p-network-dashboard)
4. [Security Dashboard](#security-dashboard)
5. [Performance Dashboard](#performance-dashboard)
6. [Infrastructure Dashboard](#infrastructure-dashboard)

---

## Overview Dashboard

### System Health

```promql
# Overall System Health Score
(
  (
    sum(rate(vigilnet_health_checks_total{status="success"}[5m]))
    /
    sum(rate(vigilnet_health_checks_total[5m]))
  ) * 100
)
```

```promql
# Service Uptime Percentage (Last 24h)
(
  sum(increase(vigilnet_uptime_seconds[24h]))
  /
  (24 * 60 * 60)
) * 100
```

```promql
# Active Nodes Count
sum(vigilnet_node_active{job="vigilnet-nodes"})
```

```promql
# Total Connected Peers
sum(vigilnet_p2p_connected_peers_total)
```

### Error Rates

```promql
# Overall Error Rate (requests per second)
sum(rate(vigilnet_errors_total[5m]))
```

```promql
# Error Rate by Type
sum by (error_type) (rate(vigilnet_errors_total[5m]))
```

```promql
# API Error Rate Percentage
(
  sum(rate(vigilnet_api_errors_total[5m]))
  /
  sum(rate(vigilnet_api_requests_total[5m]))
) * 100
```

### Request Metrics

```promql
# Total Requests per Second
sum(rate(vigilnet_api_requests_total[5m]))
```

```promql
# Requests by Endpoint
topk(10, sum by (endpoint) (rate(vigilnet_api_requests_total[5m])))
```

```promql
# Request Latency (95th percentile)
histogram_quantile(0.95,
  sum(rate(vigilnet_request_duration_seconds_bucket[5m])) by (le)
)
```

```promql
# Request Latency by Endpoint (95th percentile)
topk(10,
  histogram_quantile(0.95,
    sum(rate(vigilnet_request_duration_seconds_bucket[5m])) by (endpoint, le)
  )
)
```

---

## Agent Network Dashboard

### Agent Metrics

```promql
# Total Active Agents
sum(vigilnet_agent_active_total)
```

```promql
# Agents by Status
sum by (status) (vigilnet_agent_status)
```

```promql
# Agent Registration Rate
sum(rate(vigilnet_agent_registrations_total[5m]))
```

```promql
# Agent Disconnection Rate
sum(rate(vigilnet_agent_disconnections_total[5m]))
```

### Message Metrics

```promql
# Messages Sent per Second
sum(rate(vigilnet_agent_messages_sent_total[5m]))
```

```promql
# Messages Received per Second
sum(rate(vigilnet_agent_messages_received_total[5m]))
```

```promql
# Messages by Type
sum by (msg_type) (rate(vigilnet_agent_messages_sent_total[5m]))
```

```promql
# Average Message Size
avg(vigilnet_agent_message_size_bytes)
```

```promql
# Message Delivery Success Rate
(
  sum(rate(vigilnet_agent_messages_delivered_total[5m]))
  /
  sum(rate(vigilnet_agent_messages_sent_total[5m]))
) * 100
```

### Encryption Metrics

```promql
# E2EE Handshakes per Second
sum(rate(vigilnet_e2ee_handshakes_total[5m]))
```

```promql
# Encryption Operations Rate
sum by (operation) (rate(vigilnet_crypto_operations_total[5m]))
```

```promql
# Encryption Latency
histogram_quantile(0.99,
  sum(rate(vigilnet_crypto_operation_duration_seconds_bucket[5m])) by (le)
)
```

### Circle Metrics

```promql
# Total Active Circles
sum(vigilnet_circle_active_total)
```

```promql
# Circle Members Count
sum by (circle_id) (vigilnet_circle_members_total)
```

```promql
# Circle Message Rate
sum by (circle_id) (rate(vigilnet_circle_messages_total[5m]))
```

---

## P2P Network Dashboard

### Peer Connectivity

```promql
# Connected Peers Count
sum(vigilnet_p2p_connected_peers_total)
```

```promql
# Peer Connections by Protocol
sum by (protocol) (vigilnet_p2p_connections_total)
```

```promql
# Peer Connection Rate
sum(rate(vigilnet_p2p_connections_opened_total[5m]))
```

```promql
# Peer Disconnection Rate
sum(rate(vigilnet_p2p_connections_closed_total[5m]))
```

```promql
# Average Peer Latency
avg(vigilnet_p2p_peer_latency_seconds)
```

### Protocol Metrics

```promql
# QUIC Connections
sum(vigilnet_transport_quic_connections_active)
```

```promql
# TCP Connections
sum(vigilnet_transport_tcp_connections_active)
```

```promql
# BLE Mesh Connections
sum(vigilnet_transport_ble_connections_active)
```

```promql
# Circuit Build Rate (Tor)
sum(rate(vigilnet_tor_circuits_built_total[5m]))
```

```promql
# Circuit Failure Rate
(
  sum(rate(vigilnet_tor_circuits_failed_total[5m]))
  /
  sum(rate(vigilnet_tor_circuits_built_total[5m]))
) * 100
```

### Bandwidth Metrics

```promql
# Total Bandwidth In
sum(rate(vigilnet_p2p_bytes_received_total[5m]))
```

```promql
# Total Bandwidth Out
sum(rate(vigilnet_p2p_bytes_sent_total[5m]))
```

```promql
# Bandwidth by Peer
topk(10, sum by (peer_id) (rate(vigilnet_p2p_bytes_sent_total[5m])))
```

### DHT Metrics

```promql
# DHT Table Size
sum(vigilnet_dht_routing_table_size)
```

```promql
# DHT Query Rate
sum(rate(vigilnet_dht_queries_total[5m]))
```

```promql
# DHT Query Success Rate
(
  sum(rate(vigilnet_dht_queries_success_total[5m]))
  /
  sum(rate(vigilnet_dht_queries_total[5m]))
) * 100
```

---

## Security Dashboard

### Authentication Metrics

```promql
# Authentication Attempts Rate
sum(rate(vigilnet_auth_attempts_total[5m]))
```

```promql
# Authentication Success Rate
(
  sum(rate(vigilnet_auth_success_total[5m]))
  /
  sum(rate(vigilnet_auth_attempts_total[5m]))
) * 100
```

```promql
# Failed Authentications by Source
sum by (source_ip) (rate(vigilnet_auth_failed_total[5m]))
```

### Encryption Health

```promql
# Active Encrypted Sessions
sum(vigilnet_crypto_sessions_active)
```

```promql
# Key Rotations per Hour
sum(rate(vigilnet_crypto_key_rotations_total[1h]))
```

```promql
# Double Ratchet Steps
sum(rate(vigilnet_crypto_ratchet_steps_total[5m]))
```

```promql
# PreKey Bundle Requests
sum(rate(vigilnet_crypto_prekey_requests_total[5m]))
```

### Threat Detection

```promql
# Blocked Connections
sum(rate(vigilnet_firewall_blocked_total[5m]))
```

```promql
# Suspicious Activity Events
sum(rate(vigilnet_security_events_total{severity=~"high|critical"}[5m]))
```

```promql
# Rate Limiting Hits
sum(rate(vigilnet_rate_limit_hits_total[5m]))
```

---

## Performance Dashboard

### System Performance

```promql
# CPU Usage Percentage
(
  sum(rate(process_cpu_seconds_total{job="vigilnet-nodes"}[5m]))
  /
  count(process_cpu_seconds_total{job="vigilnet-nodes"})
) * 100
```

```promql
# Memory Usage
sum(process_resident_memory_bytes{job="vigilnet-nodes"})
```

```promql
# Memory Usage Percentage
(
  sum(process_resident_memory_bytes{job="vigilnet-nodes"})
  /
  sum(container_spec_memory_limit_bytes{container="vigilnet-node"})
) * 100
```

```promql
# Goroutines Count
sum(go_goroutines{job="vigilnet-nodes"})
```

```promql
# GC Pause Duration
histogram_quantile(0.99,
  sum(rate(go_gc_duration_seconds_bucket[5m])) by (le)
)
```

### Connection Pool Metrics

```promql
# Active Connections in Pool
sum(vigilnet_connection_pool_active)
```

```promql
# Pool Utilization Percentage
(
  sum(vigilnet_connection_pool_active)
  /
  sum(vigilnet_connection_pool_max)
) * 100
```

```promql
# Connection Wait Time
histogram_quantile(0.95,
  sum(rate(vigilnet_connection_wait_duration_seconds_bucket[5m])) by (le)
)
```

### Packet Processing

```promql
# Packets Processed per Second
sum(rate(vigilnet_tun_packets_processed_total[5m]))
```

```promql
# Packet Processing Latency
histogram_quantile(0.99,
  sum(rate(vigilnet_tun_packet_duration_seconds_bucket[5m])) by (le)
)
```

```promql
# Dropped Packets Rate
sum(rate(vigilnet_tun_packets_dropped_total[5m]))
```

---

## Infrastructure Dashboard

### Kubernetes Metrics

```promql
# Pod Status
sum by (phase) (kube_pod_status_phase{namespace="vigilnet"})
```

```promql
# Pod Restarts
sum(kube_pod_container_status_restarts_total{namespace="vigilnet"})
```

```promql
# Pod CPU Usage
sum(rate(container_cpu_usage_seconds_total{namespace="vigilnet"}[5m])) by (pod)
```

```promql
# Pod Memory Usage
sum(container_memory_usage_bytes{namespace="vigilnet"}) by (pod)
```

```promql
# Node Disk Pressure
kube_node_status_condition{condition="DiskPressure",status="true"}
```

```promql
# Node Memory Pressure
kube_node_status_condition{condition="MemoryPressure",status="true"}
```

### Network Metrics

```promql
# Network Receive Rate
sum(rate(container_network_receive_bytes_total{namespace="vigilnet"}[5m]))
```

```promql
# Network Transmit Rate
sum(rate(container_network_transmit_bytes_total{namespace="vigilnet"}[5m]))
```

```promql
# Open File Descriptors
sum(process_open_fds{job="vigilnet-nodes"})
```

### Storage Metrics

```promql
# Disk Usage
(
  sum(node_filesystem_size_bytes{mountpoint="/"})
  -
  sum(node_filesystem_avail_bytes{mountpoint="/"})
)
/
sum(node_filesystem_size_bytes{mountpoint="/"}) * 100
```

```promql
# Disk I/O Rate
sum(rate(node_disk_read_bytes_total[5m]))
```

---

## Custom Recording Rules

Add these to your Prometheus rules file for optimized querying:

```yaml
groups:
  - name: vigilnet.rules
    interval: 30s
    rules:
      # Request rates pre-aggregated
      - record: vigilnet:api_requests_rate5m
        expr: sum(rate(vigilnet_api_requests_total[5m]))

      # Error rate pre-aggregated
      - record: vigilnet:error_rate5m
        expr: |
          (
            sum(rate(vigilnet_errors_total[5m]))
            /
            sum(rate(vigilnet_api_requests_total[5m]))
          )

      # Latency percentiles pre-calculated
      - record: vigilnet:request_latency_p95
        expr: |
          histogram_quantile(0.95,
            sum(rate(vigilnet_request_duration_seconds_bucket[5m])) by (le)
          )

      - record: vigilnet:request_latency_p99
        expr: |
          histogram_quantile(0.99,
            sum(rate(vigilnet_request_duration_seconds_bucket[5m])) by (le)
          )

      # Agent message rate
      - record: vigilnet:agent_messages_rate5m
        expr: sum(rate(vigilnet_agent_messages_sent_total[5m]))

      # P2P peer connection rate
      - record: vigilnet:p2p_connection_rate5m
        expr: sum(rate(vigilnet_p2p_connections_opened_total[5m]))

      # Bandwidth rates
      - record: vigilnet:bandwidth_in_rate5m
        expr: sum(rate(vigilnet_p2p_bytes_received_total[5m]))

      - record: vigilnet:bandwidth_out_rate5m
        expr: sum(rate(vigilnet_p2p_bytes_sent_total[5m]))
```

---

## Dashboard JSON Templates

### Import URLs

- **Grafana.com Dashboards:**
  - VigilNet Overview: `https://grafana.com/dashboards/10001`
  - Agent Network: `https://grafana.com/dashboards/10002`
  - P2P Network: `https://grafana.com/dashboards/10003`
  - Security Events: `https://grafana.com/dashboards/10004`

### Local Import

```bash
# Import dashboard via API
curl -X POST \
  http://localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <API_KEY>' \
  -d @dashboard-vigilnet-overview.json
```

---

## Alert Thresholds Reference

| Metric | Warning | Critical | Evaluation |
|--------|---------|----------|------------|
| Error Rate | > 1% | > 5% | 5m |
| Request Latency (p95) | > 500ms | > 2s | 5m |
| CPU Usage | > 70% | > 90% | 5m |
| Memory Usage | > 80% | > 95% | 5m |
| Disk Usage | > 80% | > 90% | 5m |
| Peer Connectivity | < 3 peers | < 1 peer | 5m |
| Agent Message Failures | > 1% | > 5% | 5m |
| Authentication Failures | > 5% | > 20% | 5m |
| Circuit Build Failures | > 10% | > 30% | 10m |
| Service Uptime | < 99.9% | < 99% | 1h |

---

**Document Version:** 1.0.0  
**Last Updated:** 2026-02-15  
**Compatible with:** VigilNet v0.1.0+
