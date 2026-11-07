#!/usr/bin/env bash
# Build the systemd test host, run tests/linux/systemd_check.sh inside it, and clean up.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export MSYS_NO_PATHCONV=1 # Git Bash on Windows would otherwise rewrite container paths

NAME=sentinelai-systemd-test
docker build -q -f docker/systemd-test.Dockerfile -t "$NAME" . >/dev/null || exit 1
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --rm --name "$NAME" --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw "$NAME" >/dev/null || exit 1
trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT

for _ in $(seq 1 60); do
    state="$(docker exec "$NAME" systemctl is-system-running 2>/dev/null)"
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
done

docker exec "$NAME" bash /src/tests/linux/systemd_check.sh
