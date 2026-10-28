#!/usr/bin/env bash
# Brings up the reference Compose deployment (deploy/compose) from images that
# are already built, and checks it works as a whole: both ops listeners report
# ready, the data plane answers, the bootstrap bearer reaches the management
# API through the shared namespace, control talks to the edge over the signed
# apply channel, every resident job records a successful pass, management
# audit events travel journal -> seal -> publish -> ClickHouse, and edge and
# control each survive a restart.
#
# Usage: XSHIELD_IMAGE_TAG=<tag> scripts/test_compose_deployment.sh
#   Images xshield-edge, xshield-control and xshield-worker with that tag must
#   exist locally (docker build --target edge|control|worker -t xshield-<t>:<tag> .).
#
# It runs in a scratch copy of deploy/compose under its own Compose project
# and removes the project's containers and volumes afterwards. It needs the
# host ports 6400-6409, 9554 and 9555 on 127.0.0.1.
#
# Not covered: the management HTTPS proxy and the console (operator-provided,
# see deploy/compose/README.md); serving a site, because the first apply needs
# an independent approval from an OIDC browser session (covered by the
# control-plane and gateway suites, not here).
set -Eeuo pipefail
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tag=${XSHIELD_IMAGE_TAG:?set XSHIELD_IMAGE_TAG to the tag of the built images}
curl_image='curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69'
project=xshield-compose-smoke
work=$(mktemp -d)
cp "$repo_root"/deploy/compose/{compose.yaml,compose.smoke.yaml,init.sh,clickhouse-user.sh,env.example} "$work/"

compose() { docker compose -p "$project" --project-directory "$work" -f "$work/compose.yaml" -f "$work/compose.smoke.yaml" "$@"; }
fail() {
    printf 'compose deployment: FAILED: %s\n' "$1" >&2
    compose ps -a >&2 || true
    compose logs --tail 40 >&2 || true
    exit 1
}
cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

cp "$work/env.example" "$work/.env"
cat >>"$work/.env" <<EOF
XSHIELD_REPO_ROOT=$repo_root
XSHIELD_IMAGE_TAG=$tag
XSHIELD_CONTROL_OIDC_ISSUER=http://127.0.0.1:8080/realms/xshield-dev
XSHIELD_CONTROL_OIDC_CLIENT_ID=xshield-console-dev
XSHIELD_CONTROL_OIDC_REQUIRED_ACR=1
XSHIELD_CONTROL_CONSOLE_ORIGIN=http://127.0.0.1:55173
XSHIELD_CONTROL_ROLES=observer,system_admin,release_operator
XSHIELD_SEAL_INTERVAL_SECONDS=3
XSHIELD_PUBLISH_INTERVAL_SECONDS=3
XSHIELD_OUTBOX_INTERVAL_SECONDS=3
XSHIELD_ALLOWED_UPSTREAM_CIDRS=172.30.0.20/32
EOF
XSHIELD_OIDC_CLIENT_SECRET=xshield-dev-client-secret "$work/init.sh" >/dev/null
token=$(head -n 1 "$work/secrets/control_token")

ready() { curl -sf --max-time 3 "http://127.0.0.1:$1/readyz" | grep -qx '{"ready":true}'; }
wait_ready() {
    local _
    for _ in $(seq 1 "$2"); do
        ready 9554 && ready 9555 && return 0
        sleep 2
    done
    fail "$1"
}
# The management API listens on loopback inside the shared namespace only.
management() {
    docker run --rm -i --network "container:$(compose ps -q net)" "$curl_image" \
        -s --max-time 10 -H "Authorization: Bearer $token" "$@"
}

compose up -d --quiet-pull >/dev/null 2>&1 || fail 'compose up'
# Control exits until Keycloak serves discovery and is restarted; allow for it.
wait_ready 'edge and control did not become ready' 150
echo 'ok: edge and control ready'

denied=$(curl -s --max-time 5 -H 'Host: pilot.example.test' http://127.0.0.1:6400/)
grep -q '"reason_code":"SITE_CONFIG_UNAVAILABLE"' <<<"$denied" || fail "data plane: $denied"
echo 'ok: data plane refuses an unconfigured host'

sites=$(management -w '\n%{http_code}' http://127.0.0.1:9443/control/v1/sites)
[[ "${sites##*$'\n'}" == 200 ]] || fail "bootstrap bearer: $sites"
unauthenticated=$(docker run --rm --network "container:$(compose ps -q net)" "$curl_image" \
    -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9443/control/v1/sites)
[[ "$unauthenticated" == 401 ]] || fail "management API without a bearer answered $unauthenticated"
echo 'ok: management API reachable with the bootstrap bearer only'

site='{"site_id":"site_pilot","display_name":"Compose smoke","public_origin":"https://pilot.example.test","upstream_address":"172.30.0.20:8080","upstream_server_name":"origin.internal","upstream_tls":false,"listen_port":6401,"entry_path":"/","security_entry":"public","sensor_enabled":false,"policy_revision":"smoke-r1","status":"active","policy":{"routes":[{"operation_id":"smoke.home","method":"GET","path":"/","security_entry":"public"}]}}'
# Only the admitted private network may be an origin.
outside=$(management -X POST -H 'Content-Type: application/json' \
    -H 'Idempotency-Key: compose-smoke-create-0' --data-binary @- \
    http://127.0.0.1:9443/control/v1/sites <<<"${site/172.30.0.20:8080/172.30.0.21:8080}")
grep -q '"error_code":"CONTROL_SITE_SSRF_BLOCKED"' <<<"$outside" || fail "private origin outside the admitted network: $outside"
created=$(management -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' \
    -H 'Idempotency-Key: compose-smoke-create-1' --data-binary @- \
    http://127.0.0.1:9443/control/v1/sites <<<"$site")
[[ "${created##*$'\n'}" == 201 ]] || fail "site create: $created"
# The edge health in the answer comes over the signed HMAC channel.
grep -q '"edge_state":"healthy"' <<<"$created" || fail "edge health over the apply channel: $created"
applied=$(management -X POST -H 'Idempotency-Key: compose-smoke-apply-1' \
    http://127.0.0.1:9443/control/v1/sites/site_pilot/apply)
# A first apply waits for an independent approval.
grep -q '"reason_code":"CONTROL_SITE_APPROVAL_REQUIRED"' <<<"$applied" || fail "apply: $applied"
echo 'ok: admitted private origin saved, others refused; control reached the edge over the signed channel; apply waits for approval'

metrics=$(curl -s --max-time 5 http://127.0.0.1:9555/metrics)
grep -q '^xshield_control_responses_total{class="2xx"} [1-9]' <<<"$metrics" || fail 'control metrics did not count the 2xx responses'
grep -q '^xshield_control_ready 1$' <<<"$metrics" || fail 'control metrics do not report ready'
echo 'ok: control metrics count management responses'

# A restart starts a new journal segment, which closes the previous one.
compose restart control >/dev/null 2>&1 || fail 'restart control'
compose restart edge >/dev/null 2>&1 || fail 'restart edge'
wait_ready 'edge and control did not recover after a restart' 60
echo 'ok: edge and control ready again after restarts'

jobs=(edge-seal edge-publish control-seal control-publish)
for family in case evidence_catalog evidence_access evidence_retention calibration \
    identity grant response_grant share_grant ui_action; do
    jobs+=("outbox-$family")
done
published=0
for _ in $(seq 1 60); do
    published=$(compose exec -T clickhouse clickhouse-client --query \
        "SELECT count() FROM xshield.audit_events WHERE event_type = 'console.site.create'" 2>/dev/null || echo 0)
    [[ "$published" -ge 1 ]] && break
    sleep 2
done
[[ "$published" -ge 1 ]] || fail 'management audit events did not reach ClickHouse'
echo 'ok: management audit events sealed, published and indexed'

now=$(date +%s)
for job in "${jobs[@]}"; do
    beat=$(compose exec -T edge-seal cat "/var/lib/xshield/heartbeat/$job" 2>/dev/null || true)
    [[ "$beat" =~ ^[0-9]+$ ]] || fail "$job has not recorded a successful pass"
    ((now - beat < 60)) || fail "$job heartbeat is stale ($((now - beat)) s)"
done
echo "ok: all ${#jobs[@]} resident jobs record successful passes"

restarting=$(compose ps -a --format '{{.Service}} {{.State}}' | awk '$2 != "running" && $1 != "volumes-init"')
[[ -z "$restarting" ]] || fail "services not running: $restarting"
echo 'compose deployment smoke passed'
