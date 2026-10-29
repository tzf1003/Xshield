#!/usr/bin/env bash
# Validates deploy/prometheus/alerts.yml with `promtool check rules`, via the
# official Prometheus image so no local install is required.
#
# Usage: scripts/test_prometheus_alerts.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

image="prom/prometheus@sha256:565ee86501224ebbb98fc10b332fa54440b100469924003359edf49cbce374bd"

docker run --rm -v "$PWD/deploy/prometheus:/rules:ro" "$image" \
    promtool check rules /rules/alerts.yml
