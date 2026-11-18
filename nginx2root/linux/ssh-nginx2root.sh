#!/bin/sh
set -u

SCRIPT=${DETECT:-$(dirname "$0")/detect-nginx2root.sh}
HOSTS=${1:?usage: ssh-nginx2root.sh hosts.txt [results_dir]}
OUT=${2:-results}
PARALLEL=${PARALLEL:-10}
SUDO=${SUDO-sudo -n}
DETECT_ARGS=${DETECT_ARGS:-}

[ -f "$SCRIPT" ] || { echo "detector not found at $SCRIPT (set DETECT=/path/to/detect-nginx2root.sh)" >&2; exit 3; }
[ -f "$HOSTS" ]  || { echo "hosts file not found: $HOSTS" >&2; exit 3; }
mkdir -p "$OUT" || exit 3
rm -f "$OUT"/.status.* 2>/dev/null

safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._@-' '_'; }

ENVP=""
for v in NGINX2ROOT_FIXED_PKGS NGINX2ROOT_FIXED_IN; do
    eval "isset=\${$v+yes}; val=\${$v-}"
    [ "${isset:-}" = yes ] || continue
    case "$val" in
        *[!A-Za-z0-9\ ._:+~=-]*) echo "$v has characters that cannot be passed over SSH" >&2; exit 3 ;;
    esac
    ENVP="$ENVP $v='$val'"
done
[ -n "$ENVP" ] && ENVP="env$ENVP"

one() {
    h=$1
    s=$(safe "$h")
    f="$OUT/$s.txt"
    if ssh -o BatchMode=yes -o ConnectTimeout=15 "$h" "$SUDO $ENVP bash -s -- $DETECT_ARGS" < "$SCRIPT" > "$f" 2>"$f.err"; then
        rc=0
    else
        rc=$?
    fi
    case "$rc" in
        0) v="not impacted" ;;
        1) v="impacted" ;;
        2) v="unknown" ;;
        3) v="error (usage)" ;;
        255) v="error (ssh/connection)" ;;
        *) v="error (rc=$rc)" ;;
    esac
    printf '%s\t%s\n' "$v" "$h" > "$OUT/.status.$s"
    grep -E '^CVE-[0-9]+-[0-9]+: ' "$f" 2>/dev/null | while IFS= read -r l; do
        printf '%s\t%s\t%s\n' "${l%%:*}" "${l#*: }" "$h"
    done > "$OUT/.cve.$s"
    [ -s "$f.err" ] || rm -f "$f.err"
}

n=0
while IFS= read -r h || [ -n "$h" ]; do
    case "$h" in ''|\#*) continue ;; esac
    one "$h" &
    n=$((n + 1))
    [ $((n % PARALLEL)) -eq 0 ] && wait
done < "$HOSTS"
wait

cat "$OUT"/.status.* 2>/dev/null > "$OUT/.all" || true
cat "$OUT"/.cve.* 2>/dev/null > "$OUT/.cves" || true
echo "nginx2root fleet detection ($n host(s))"
for v in impacted unknown "not impacted"; do
    hs=$(awk -F'\t' -v V="$v" '$1==V{print $2}' "$OUT/.all" 2>/dev/null | sort | tr '\n' ' ')
    printf '  %-13s %s\n' "$v:" "${hs:-(none)}"
done
errs=$(awk -F'\t' '$1 ~ /^error/{printf "%s(%s) ", $2, $1}' "$OUT/.all" 2>/dev/null)
[ -n "$errs" ] && printf '  %-13s %s\n' "error:" "$errs"
echo "impacted hosts by CVE"
for c in CVE-2026-123007 CVE-2026-123633 CVE-2026-121810 CVE-2026-123634 CVE-2026-113425; do
    hs=$(awk -F'\t' -v C="$c" '$1==C && $2=="impacted"{print $3}' "$OUT/.cves" 2>/dev/null | sort | tr '\n' ' ')
    printf '  %s: %s\n' "$c" "${hs:-(none)}"
done
echo "per-host output in $OUT/"
rm -f "$OUT"/.status.* "$OUT"/.cve.* 2>/dev/null

if awk -F'\t' '$1=="impacted"{f=1} END{exit !f}' "$OUT/.all" 2>/dev/null; then exit 1; fi
if awk -F'\t' '$1=="unknown" || $1 ~ /^error/{f=1} END{exit !f}' "$OUT/.all" 2>/dev/null; then exit 2; fi
exit 0
