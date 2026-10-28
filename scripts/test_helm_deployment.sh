#!/usr/bin/env bash
# Installs the Helm chart (deploy/helm/xshield) into the current Kubernetes
# context and checks it works as a whole, as scripts/test_compose_deployment.sh
# does for Compose: edge and control ready, the data plane answers through its
# Service, the bootstrap bearer reaches the loopback-only management API from
# inside the pod, an admitted private origin is saved while one outside the
# admitted network is refused, control reaches the edge over the signed apply
# channel, management audit events travel journal -> seal -> publish ->
# ClickHouse, every resident job records successful passes, and the pod comes
# back on its persistent volume after being deleted.
#
# Usage: XSHIELD_IMAGE_TAG=<tag> scripts/test_helm_deployment.sh
#   Images xshield-edge, xshield-control and xshield-worker with that tag must
#   already be on the cluster's nodes (CI: `kind load docker-image`); the chart
#   uses imagePullPolicy Never. Needs kubectl, helm and openssl.
#
# It works in its own namespace and deletes it afterwards, unless
# XSHIELD_SMOKE_KEEP=1. Not covered, as in the Compose smoke: serving a site
# (the first apply needs an independent approval from an OIDC browser
# session), the management HTTPS proxy and console, a real IdP, TLS and MFA.
set -Eeuo pipefail
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tag=${XSHIELD_IMAGE_TAG:?set XSHIELD_IMAGE_TAG to the tag of the images on the nodes}
ns=xshield-helm-smoke
release=xshield
pod=xshield-0
work=$(mktemp -d)

k() { kubectl -n "$ns" "$@"; }
fail() {
    printf 'helm deployment: FAILED: %s\n' "$1" >&2
    k get pods -o wide >&2 || true
    k describe pod "$pod" 2>/dev/null | tail -n 60 >&2 || true
    k logs "$pod" --all-containers --prefix --tail 30 >&2 || true
    k logs deploy/xshield-outbox --all-containers --prefix --tail 10 >&2 || true
    exit 1
}
cleanup() {
    if [[ "${XSHIELD_SMOKE_KEEP:-}" != 1 ]]; then
        kubectl delete namespace "$ns" --wait=false >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

kubectl create namespace "$ns" >/dev/null
db_password=$(openssl rand -hex 24)
ch_password=$(openssl rand -hex 24)
k create secret generic smoke-databases \
    --from-literal=postgres_password="$db_password" \
    --from-literal=clickhouse_password="$ch_password" >/dev/null
k create configmap smoke-migrations --from-file="$repo_root/migrations" >/dev/null
k create configmap smoke-clickhouse-init \
    --from-file=001-schema.sql="$repo_root/sql/clickhouse.sql" \
    --from-file=002-user.sh="$repo_root/deploy/compose/clickhouse-user.sh" >/dev/null
k create configmap smoke-realm --from-file="$repo_root/dev/keycloak/xshield-dev-realm.json" >/dev/null
k apply -f "$repo_root/deploy/helm/smoke/deps.yaml" >/dev/null
k wait --for=condition=Ready pod/smoke-origin --timeout=180s >/dev/null || fail 'origin did not start'
origin_ip=$(k get pod smoke-origin -o jsonpath='{.status.podIP}')
k rollout status deploy/smoke-postgres --timeout=300s >/dev/null || fail 'PostgreSQL did not become ready'
k rollout status deploy/smoke-clickhouse --timeout=300s >/dev/null || fail 'ClickHouse did not become ready'
echo 'ok: test dependencies ready'

XSHIELD_DATABASE_URL="postgresql://xshield:$db_password@postgres:5432/xshield" \
    XSHIELD_CLICKHOUSE_PASSWORD="$ch_password" \
    XSHIELD_OIDC_CLIENT_SECRET=xshield-dev-client-secret \
    "$repo_root/deploy/helm/xshield-secrets.sh" "$work/secrets" >/dev/null
k create secret generic xshield --from-file="$work/secrets" >/dev/null
token=$(cat "$work/secrets/control_token")

helm install "$release" "$repo_root/deploy/helm/xshield" -n "$ns" \
    -f "$repo_root/deploy/helm/smoke/values.yaml" \
    --set "images.edge=xshield-edge:$tag" \
    --set "images.control=xshield-control:$tag" \
    --set "images.worker=xshield-worker:$tag" \
    --set-json "control.allowedUpstreamCidrs=[\"$origin_ip/32\"]" \
    --wait --timeout 10m >/dev/null || fail 'helm install'

in_pod() { k exec "$pod" -c toolbox -- curl -s --max-time 10 "$@"; }
ready() {
    local ip
    ip=$(k get pod "$pod" -o jsonpath='{.status.podIP}')
    in_pod "http://$ip:9554/readyz" | grep -qx '{"ready":true}' &&
        in_pod "http://$ip:9555/readyz" | grep -qx '{"ready":true}'
}
wait_ready() {
    local _
    for _ in $(seq 1 150); do
        ready 2>/dev/null && return 0
        sleep 2
    done
    fail "$1"
}
# Control exits until Keycloak serves discovery and is restarted; allow for it.
wait_ready 'edge and control did not become ready'
echo 'ok: edge and control ready'

denied=$(in_pod -H 'Host: pilot.example.test' "http://$release-edge:6400/")
grep -q '"reason_code":"SITE_CONFIG_UNAVAILABLE"' <<<"$denied" || fail "data plane: $denied"
echo 'ok: data plane refuses an unconfigured host through its Service'

management() { in_pod -H "Authorization: Bearer $token" "$@"; }
sites=$(management -w '\n%{http_code}' http://127.0.0.1:9443/control/v1/sites)
[[ "${sites##*$'\n'}" == 200 ]] || fail "bootstrap bearer: $sites"
unauthenticated=$(in_pod -o /dev/null -w '%{http_code}' http://127.0.0.1:9443/control/v1/sites)
[[ "$unauthenticated" == 401 ]] || fail "management API without a bearer answered $unauthenticated"
echo 'ok: management API reachable in the pod with the bootstrap bearer only'

site='{"site_id":"site_pilot","display_name":"Helm smoke","public_origin":"https://pilot.example.test","upstream_address":"ORIGIN:8080","upstream_server_name":"origin.internal","upstream_tls":false,"listen_port":6401,"entry_path":"/","security_entry":"public","sensor_enabled":false,"policy_revision":"smoke-r1","status":"active","policy":{"routes":[{"operation_id":"smoke.home","method":"GET","path":"/","security_entry":"public"}]}}'
outside=$(management -X POST -H 'Content-Type: application/json' \
    -H 'Idempotency-Key: helm-smoke-create-0' --data-binary "${site/ORIGIN/10.255.255.254}" \
    http://127.0.0.1:9443/control/v1/sites)
grep -q '"error_code":"CONTROL_SITE_SSRF_BLOCKED"' <<<"$outside" || fail "private origin outside the admitted network: $outside"
created=$(management -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
    -H 'Idempotency-Key: helm-smoke-create-1' --data-binary "${site/ORIGIN/$origin_ip}" \
    http://127.0.0.1:9443/control/v1/sites)
[[ "${created##*$'\n'}" == 201 ]] || fail "site create: $created"
grep -q '"edge_state":"healthy"' <<<"$created" || fail "edge health over the apply channel: $created"
applied=$(management -X POST -H 'Idempotency-Key: helm-smoke-apply-1' \
    http://127.0.0.1:9443/control/v1/sites/site_pilot/apply)
grep -q '"reason_code":"CONTROL_SITE_APPROVAL_REQUIRED"' <<<"$applied" || fail "apply: $applied"
echo 'ok: admitted private origin saved, others refused; control reached the edge over the signed channel; apply waits for approval'

published=0
for _ in $(seq 1 60); do
    published=$(k exec deploy/smoke-clickhouse -- clickhouse-client --query \
        "SELECT count() FROM xshield.audit_events WHERE event_type = 'console.site.create'" 2>/dev/null || echo 0)
    [[ "$published" -ge 1 ]] && break
    sleep 2
done
[[ "$published" -ge 1 ]] || fail 'management audit events did not reach ClickHouse'
echo 'ok: management audit events sealed, published and indexed'

fresh() {
    local beat now
    beat=$(k exec "$1" -c "$2" -- cat "/var/lib/xshield/heartbeat/$3" 2>/dev/null || true)
    now=$(date +%s)
    [[ "$beat" =~ ^[0-9]+$ ]] || fail "$3 has not recorded a successful pass"
    ((now - beat < 60)) || fail "$3 heartbeat is stale ($((now - beat)) s)"
}
for job in edge-seal edge-publish control-seal control-publish; do
    fresh "$pod" "$job" "$job"
done
for family in case evidence_catalog evidence_access evidence_retention calibration \
    identity grant response_grant share_grant ui_action; do
    fresh deploy/xshield-outbox "${family//_/-}" "outbox-$family"
done
echo 'ok: all 14 resident jobs record successful passes'

# The edge, the jobs and the outbox publishers never restarted (control may
# have, while Keycloak was starting).
restarts=$(k get pods -l app.kubernetes.io/instance="$release" -o \
    jsonpath='{range .items[*].status.containerStatuses[*]}{.name}={.restartCount}{"\n"}{end}' |
    awk -F= '$1 != "control" && $1 != "oidc" && $2 != 0')
[[ -z "$restarts" ]] || fail "containers restarted: $restarts"
echo 'ok: no edge, job or outbox container restarted'

# A new pod (and pod IP) on the same volume: the edge re-renders its listen
# address, the journals carry on, the saved site is still there.
k delete pod "$pod" --wait=true >/dev/null || fail 'delete pod'
k rollout status statefulset/"$release" --timeout=10m >/dev/null || fail 'pod did not come back'
wait_ready 'edge and control did not recover on a new pod'
sites=$(management http://127.0.0.1:9443/control/v1/sites)
grep -q '"site_id":"site_pilot"' <<<"$sites" || fail "site missing after the pod was replaced: $sites"
echo 'ok: a replaced pod is ready again on the same volume'
echo 'helm deployment smoke passed'
