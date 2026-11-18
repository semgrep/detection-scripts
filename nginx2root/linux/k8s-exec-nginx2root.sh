#!/bin/sh
set -u

SCRIPT=${DETECT:-$(dirname "$0")/detect-nginx2root.sh}
[ -f "$SCRIPT" ] || { echo "detector not found at $SCRIPT (set DETECT=/path/to/detect-nginx2root.sh)" >&2; exit 3; }
[ $# -gt 0 ] || set -- -A

NL='
'
LIST=$(kubectl get pods "$@" --field-selector=status.phase=Running \
    -o go-template='{{range .items}}{{$ns := .metadata.namespace}}{{$pod := .metadata.name}}{{$node := .spec.nodeName}}{{range .spec.containers}}{{$ns}} {{$pod}} {{.name}} {{$node}}{{"\n"}}{{end}}{{end}}') || exit 3

imp=0; unk=0; ok=0
IFS=$NL
for line in $LIST; do
    IFS=' '
    set -- $line
    ns=$1; pod=$2; ctr=$3; node=$4
    printf '=== %s/%s/%s (node %s) ===\n' "$ns" "$pod" "$ctr" "$node"
    if kubectl exec -n "$ns" "$pod" -c "$ctr" -- sh -c 'command -v bash >/dev/null 2>&1' >/dev/null 2>&1; then
        out=$(kubectl exec -i -n "$ns" "$pod" -c "$ctr" -- \
            env "NGINX2ROOT_FIXED_PKGS=${NGINX2ROOT_FIXED_PKGS:-}" "NGINX2ROOT_FIXED_IN=${NGINX2ROOT_FIXED_IN-1.30.7 1.31.9}" \
            bash -s -- --no-kernel < "$SCRIPT" 2>/dev/null)
        printf '%s\n' "$out"
        case "$(printf '%s\n' "$out" | tail -1)" in
            impacted) imp=$((imp + 1)) ;;
            "not impacted") ok=$((ok + 1)) ;;
            *) unk=$((unk + 1)) ;;
        esac
    else
        echo "unknown: no bash in this container; use the DaemonSet (k8s-nginx2root.yaml)"
        unk=$((unk + 1))
    fi
    IFS=$NL
done
IFS=' '

echo "---"
echo "nginx2root containers: $imp impacted, $unk unknown, $ok not impacted"
[ "$imp" -gt 0 ] && exit 1
[ "$unk" -gt 0 ] && exit 2
exit 0
