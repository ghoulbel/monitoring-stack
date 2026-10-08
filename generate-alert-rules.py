#!/usr/bin/env python3
"""Render the Homelab alert rules into Grafana 11 unified-alerting format.

Grafana 11 dropped the legacy Prometheus-style `expr:` field. Every rule now
needs an explicit query + threshold-condition pair under `data:`, which is
verbose enough that hand-editing invites mistakes. Keep the readable source in
RULES below and regenerate with this script.
"""
import sys
import textwrap

DS = "prometheus"

RULES = [
    # (name, expr, for, severity, summary, description)
    ("HostFilesystemCritical",
     '100 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs|fuse.*"}'
     ' / node_filesystem_size_bytes{fstype!~"tmpfs|overlay|squashfs|fuse.*"} * 100) > 90',
     "10m", "critical",
     "Filesystem {{ $labels.mountpoint }} is {{ $value | printf \"%.1f\" }}% full",
     "Less than 10% free on {{ $labels.device }}. This is what stopped the editor "
     "mid-migration. Check /var/lib/containerd first: docker system df shows reclaimable bytes."),

    ("HostFilesystemWarning",
     '100 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs|fuse.*"}'
     ' / node_filesystem_size_bytes{fstype!~"tmpfs|overlay|squashfs|fuse.*"} * 100) > 80',
     "30m", "warning",
     "Filesystem {{ $labels.mountpoint }} is {{ $value | printf \"%.1f\" }}% full",
     "Free space is trending low; investigate before it becomes critical."),

    ("HostFilesystemAlmostOutOfInodes",
     '100 - (node_filesystem_files_free{fstype!~"tmpfs|overlay|squashfs|fuse.*"}'
     ' / node_filesystem_files{fstype!~"tmpfs|overlay|squashfs|fuse.*"} * 100) > 10',
     "30m", "warning",
     "Inodes nearly exhausted on {{ $labels.mountpoint }}",
     "Fewer than 10% of inodes free. Usually a huge number of small files."),

    ("HostOutOfMemory",
     "node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100 < 10",
     "10m", "critical",
     "Less than 10% memory available",
     "Swap thrashing is likely. ollama and ComfyUI are the usual culprits here."),

    ("KopiaSourceSnapshotStale",
     'kopia_snapshot_age_seconds{source=~"/source|/hostconfig"} > 93600',
     "30m", "critical",
     "Kopia source {{ $labels.source }} has not snapshotted in over 26 hours",
     "The daily schedule is 03:17, so a healthy host is never more than a day "
     "behind. A stale source means backups are not running. Check the kopia "
     "container and that /mnt/synology is still mounted."),

    ("KopiaWeeklySourceSnapshotStale",
     'kopia_snapshot_age_seconds{source="/source/arr-stack/config"} > 691200',
     "1h", "warning",
     "Kopia arr-stack/config has not snapshotted in over 8 days",
     "This source runs weekly (Sunday 04:41), so 8 days means it missed a run."),

    ("KopiaMetricsMissing",
     "absent(kopia_snapshot_age_seconds)",
     "2h", "warning",
     "Kopia freshness metrics are missing",
     "kopia-metrics.timer may have failed, so backup staleness cannot be detected."),

    ("CloudflaredTunnelDown",
     "cloudflared_active == 0",
     "5m", "critical",
     "The Cloudflare tunnel connector is not running",
     "All nine public hostnames will return Cloudflare 1033. "
     "Check: systemctl status cloudflared"),

    ("CloudflaredNoRegisteredConnections",
     "cloudflared_connections < 1",
     "10m", "critical",
     "cloudflared is running but has no registered tunnel connection",
     "The process is up but is not connected to any Cloudflare edge. This is "
     "the exact state that produced error 1033, and it is different from the "
     "process being down."),

    ("PrometheusTargetDown",
     "up == 0",
     "15m", "warning",
     "Prometheus target {{ $labels.job }} is down",
     "Instance {{ $labels.instance }} has been unreachable for 15 minutes."),

    ("GrafanaDown",
     'up{job="grafana"} == 0',
     "10m", "critical",
     "Grafana is not responding",
     "This is how the rest of the estate is observed, so treat it as high priority."),

    ("SynologyMountMissing",
     'absent(node_filesystem_avail_bytes{mountpoint="/mnt/synology"})',
     "10m", "critical",
     "/mnt/synology is not mounted",
     "The NAS holds the Kopia repository and all media. Without it the "
     "backup-stack has nowhere to write and every arr path is empty."),
]

GROUPS = [
    ("host", "5m", RULES[0:4]),
    ("backups", "15m", RULES[4:7]),
    ("services", "1m", RULES[7:11]),
    ("storage", "10m", RULES[11:12]),
]


def uid(name):
    out, prev = "", ""
    for i, ch in enumerate(name):
        if ch.isupper() and i and not name[i - 1].isupper():
            out += "-"
        out += ch.lower()
    return out


def block(name, expr, for_, sev, summary, desc):
    q = "\n".join("                " + l for l in textwrap.wrap(expr, 72))
    s = "\n".join("            " + l for l in textwrap.wrap(summary.replace("\n", " "), 72))
    d = "\n".join("            " + l for l in textwrap.wrap(desc, 72))
    return f"""      - alert: {name}
        uid: {uid(name)}
        title: {name}
        condition: C
        for: {for_}
        isPaused: false
        annotations:
          summary: >-
{s}
          description: >-
{d}
        labels:
          severity: {sev}
        data:
          - refId: A
            relativeTimeRange:
              from: 600
              to: 0
            datasourceUid: {DS}
            model:
              editorMode: code
              expr: >-
{q}
              instant: true
              intervalMs: 1000
              maxDataPoints: 43200
              refId: A
          - refId: C
            relativeTimeRange:
              from: 0
              to: 0
            datasourceUid: __expr__
            model:
              conditions:
                - evaluator:
                    params: [0]
                    type: gt
                  operator:
                    type: and
                  query:
                    params: [A]
                  reducer:
                    params: []
                    type: last
                  type: query
              expression: A
              refId: C
              type: threshold
"""


out = ["apiVersion: 1",
       "",
       "# GENERATED by monitoring-stack/generate-alert-rules.py - do not hand-edit.",
       "# Grafana 11 unified-alerting format. Rules cover the failure modes this",
       "# migration actually hit: a silently full disk, a tunnel that drops while",
       "# every app behind it stays healthy, and backups that stop without saying so.",
       "groups:"]
for gname, interval, rules in GROUPS:
    out.append(f"  - name: {gname}")
    out.append(f"    interval: {interval}")
    out.append("    folder: Homelab")
    out.append("    rules:")
    for r in rules:
        out.append(block(*r))

text = "\n".join(out)
dest = sys.argv[1] if len(sys.argv) > 1 else "homelab.yaml"
open(dest, "w").write(text)
print(f"wrote {dest}: {sum(len(g[2]) for g in GROUPS)} rules in {len(GROUPS)} groups")
