#!/usr/bin/env bash
# k8s-exec-php-criticals.sh -- kubectl exec the PHP-criticals (2026-11-19)
# detector into running containers that bundle PHP, and roll up the verdicts.
#
# BEST-EFFORT TRIAGE AID. Read-only on targets. No warranty: a "not impacted"
# verdict is the detector's opinion of what it could see inside the container,
# not proof of safety.
#
# What it does
#   Lists Running pods (by namespace / label selector), and for every container
#   runs detect-php-criticals.sh (the file next to this wrapper) with -q via
#   `kubectl exec`, recording the detector's final verdict line and exit code.
#   The wrapper contains NO CVE logic. By default the detector is piped over
#   stdin and run in memory (`bash -s`), so nothing is written into the
#   container; -c writes it to a mktemp file in the container, runs it and
#   removes it. Containers where a quick probe sees no PHP at all are listed as
#   "skipped" (use -a to run the detector everywhere). The detector needs bash
#   IN the container: PHP containers without bash (e.g. stock php:*-alpine) are
#   reported "unknown".
#
#   This checks PHP shipped inside application images. For PHP installed on the
#   nodes themselves use the DaemonSet (k8s-php-criticals.yaml).
#
# Required access / permissions
#   - kubectl configured for the cluster.
#   - RBAC: get/list on pods, and create on pods/exec, in the namespaces checked.
#   - The exec runs as the container's own user; unreadable config in the
#     container makes the detector answer "unknown".
#
# Per-container output
#   ns/pod/container: <verdict> (exit N)     impacted | not impacted | unknown
#   ns/pod/container: skipped (no PHP found by probe)
#   ns/pod/container: error: <reason> (exit N)
#
# Exit codes
#   0  every checked container answered "not impacted"
#   1  at least one container is impacted
#   2  nobody impacted, but at least one unknown/error, or no pods matched
#   3  usage error / detector or kubectl not found / pod listing failed
set -u

# Stop Git Bash (MSYS) on Windows from rewriting /paths in kubectl arguments.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

PROG=${0##*/}
HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
DETECTOR=${DETECT:-$HERE/detect-php-criticals.sh}
DETECT_ARGS=${DETECT_ARGS:-}
KUBECTL=${KUBECTL:-kubectl}
NS=""; ALL_NS=0; SELECTOR=""; CONTAINER=""; CONTEXT=""
COPY=0; PROBE=1; VERBOSE=0; OUTDIR=""

usage() {
    cat <<EOF
Usage: $PROG [options]

kubectl exec detect-php-criticals.sh -q into every running container that
bundles PHP and print "ns/pod/container: <verdict> (exit N)" plus a roll-up.
Best-effort triage aid, read-only on targets, no warranty.

Selection:
  -n NAMESPACE    one namespace (default: all namespaces)
  -A              all namespaces (the default when -n is not given)
  -l SELECTOR     pod label selector, e.g. -l app=web or -l 'tier in (php,fpm)'
  -C CONTAINER    only containers with this name
  --context CTX   kubectl context to use

Options:
  -a              run the detector in every selected container, even where the
                  probe sees no PHP (those would otherwise be "skipped")
  -c              copy mode: write the detector to a mktemp file in the
                  container, run it, remove it (default: pipe over stdin,
                  nothing written)
  -d DIR          keep each container's full detector output in DIR/
  -v              also print each container's per-CVE lines
  -h              this help

Environment:
  DETECT          path to the detector (default: next to this wrapper)
  DETECT_ARGS     extra detector arguments appended after -q
  KUBECTL         kubectl binary to use (default: kubectl)

Exit codes:
  0 all not impacted   1 >=1 container impacted
  2 >=1 unknown/error (none impacted), or no pods matched
  3 usage error, detector/kubectl missing, or pod listing failed
EOF
}

die_usage() { echo "$PROG: $*" >&2; echo "Try '$PROG -h' for usage." >&2; exit 3; }
need_val() { [ "$2" -ge 2 ] || die_usage "option $1 needs a value"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -n|--namespace) need_val "$1" $#; NS=$2; shift ;;
        -A|--all-namespaces) ALL_NS=1 ;;
        -l|--selector) need_val "$1" $#; SELECTOR=$2; shift ;;
        -C) need_val "$1" $#; CONTAINER=$2; shift ;;
        --context) need_val "$1" $#; CONTEXT=$2; shift ;;
        -a) PROBE=0 ;;
        -c) COPY=1 ;;
        -d) need_val "$1" $#; OUTDIR=$2; shift ;;
        -v) VERBOSE=1 ;;
        *) die_usage "unknown argument: $1" ;;
    esac
    shift
done
[ -n "$NS" ] && [ "$ALL_NS" = 1 ] && die_usage "use either -n NAMESPACE or -A, not both"

[ -f "$DETECTOR" ] || { echo "$PROG: detector not found at $DETECTOR (set DETECT=/path/to/detect-php-criticals.sh)" >&2; exit 3; }
command -v "$KUBECTL" >/dev/null 2>&1 || { echo "$PROG: $KUBECTL not found in PATH" >&2; exit 3; }

KCTL=("$KUBECTL")
[ -n "$CONTEXT" ] && KCTL+=(--context "$CONTEXT")
GET_ARGS=(--field-selector=status.phase=Running)
if [ -n "$NS" ]; then GET_ARGS+=(-n "$NS"); else GET_ARGS+=(-A); fi
[ -n "$SELECTOR" ] && GET_ARGS+=(-l "$SELECTOR")

if [ -n "$OUTDIR" ]; then
    mkdir -p "$OUTDIR" || exit 3
    WORK=$OUTDIR
    trap 'rm -f "$WORK"/.status.all "$WORK"/.list "$WORK"/.detector.sh 2>/dev/null' EXIT
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/phpcrit-k8s.XXXXXX") || exit 3
    trap 'rm -rf "$WORK"' EXIT
fi
ALL=$WORK/.status.all
: > "$ALL"

# Transport hygiene only: send an LF-only copy of the detector.
PAYLOAD=$WORK/.detector.sh
tr -d '\r' < "$DETECTOR" > "$PAYLOAD" || exit 3

"${KCTL[@]}" get pods "${GET_ARGS[@]}" \
    -o go-template='{{range .items}}{{$ns := .metadata.namespace}}{{$pod := .metadata.name}}{{range .spec.containers}}{{$ns}} {{$pod}} {{.name}}{{"\n"}}{{end}}{{end}}' \
    > "$WORK/.list" || { echo "$PROG: kubectl get pods failed" >&2; exit 3; }

# Target selection only (is there any PHP here, is there a bash to run the
# detector with); every CVE decision is the detector's.
PROBE_CMD='b=0; p=0; command -v bash >/dev/null 2>&1 && b=1
for x in php php-fpm php-cgi frankenphp; do command -v "$x" >/dev/null 2>&1 && p=1; done
for x in /usr/bin/php* /usr/sbin/php* /usr/local/bin/php* /usr/local/sbin/php* /opt/*/bin/php* /opt/*/sbin/php* /opt/*/*/bin/php* /etc/php* /usr/local/etc/php* /usr/lib/apache2/modules/libphp* /usr/lib*/httpd/modules/libphp* /etc/httpd/modules/libphp* /usr/local/apache2/modules/libphp*; do [ -e "$x" ] && p=1; done
echo "phpcrit-probe bash=$b php=$p"'

if [ "$COPY" = 1 ]; then
    RUN_CMD="f=\$(mktemp \"\${TMPDIR:-/tmp}/phpcrit.XXXXXX\") || exit 97; cat >\"\$f\" || { rm -f \"\$f\"; exit 97; }; bash \"\$f\" -q $DETECT_ARGS </dev/null; rc=\$?; rm -f \"\$f\"; exit \$rc"
else
    RUN_CMD="exec bash -s -- -q $DETECT_ARGS"
fi

safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._@-' '_'; }
last_line() { tr -d '\r' < "$1" | awk 'NF { l = $0 } END { print l }'; }

# classify LAST_LINE RC -> impacted | not impacted | unknown | error
# A verdict needs the detector's final verdict line; if line and exit code
# disagree the worse of the two wins.
classify() {
    case "$1" in
        impacted|"not impacted"|unknown) ;;
        *) echo error; return ;;
    esac
    if [ "$1" = impacted ] || [ "$2" = 1 ]; then echo impacted
    elif [ "$1" = unknown ] || [ "$2" != 0 ]; then echo unknown
    else echo "not impacted"
    fi
}

record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$ALL"; }

n=0
while read -r ns pod ctr <&3; do
    [ -n "$ns" ] && [ -n "$pod" ] && [ -n "$ctr" ] || continue
    [ -n "$CONTAINER" ] && [ "$ctr" != "$CONTAINER" ] && continue
    n=$((n + 1))
    t="$ns/$pod/$ctr"
    f="$WORK/$(printf '%04d' "$n")_$(safe "$ns.$pod.$ctr").txt"

    probe=$("${KCTL[@]}" exec -n "$ns" "$pod" -c "$ctr" -- sh -c "$PROBE_CMD" </dev/null 2>"$f.err" | tr -d '\r')
    case "$probe" in
        *"phpcrit-probe bash="*) ;;
        *)
            e=$(tr -d '\r' < "$f.err" | awk 'NF { l = $0 } END { print substr(l, 1, 120) }')
            echo "$t: error: cannot exec sh in container${e:+: $e} (exit -)"
            record error - "$t"; continue ;;
    esac
    if [ "$PROBE" = 1 ]; then
        case "$probe" in *"php=0"*)
            echo "$t: skipped (no PHP found by probe)"
            record skipped - "$t"; rm -f "$f.err"; continue ;;
        esac
    fi
    case "$probe" in *"bash=0"*)
        echo "$t: unknown (exit -; no bash in container, detector cannot run)"
        record unknown - "$t"; rm -f "$f.err"; continue ;;
    esac

    "${KCTL[@]}" exec -i -n "$ns" "$pod" -c "$ctr" -- sh -c "$RUN_CMD" < "$PAYLOAD" > "$f" 2> "$f.err"
    rc=$?
    line=$(last_line "$f")
    class=$(classify "$line" "$rc")
    if [ "$class" = error ]; then
        e=$(tr -d '\r' < "$f.err" | awk 'NF { l = $0 } END { print substr(l, 1, 120) }')
        echo "$t: error: no verdict line from detector${e:+: $e} (exit $rc)"
    elif [ "$class" != "$line" ]; then
        echo "$t: $class (exit $rc; verdict line was \"$line\")"
    else
        echo "$t: $class (exit $rc)"
    fi
    [ "$VERBOSE" = 1 ] && tr -d '\r' < "$f" | awk '$1 ~ /^CVE-[0-9]+-[0-9]+$/ { print "    " $0 }'
    record "$class" "$rc" "$t"
    [ -s "$f.err" ] || rm -f "$f.err"
done 3< "$WORK/.list"

if [ "$n" -eq 0 ]; then
    echo "$PROG: no running pods/containers matched the selection; nothing checked" >&2
    exit 2
fi

count() { awk -F'\t' -v V="$1" '$1 == V { c++ } END { print c + 0 }' "$ALL"; }
names() { awk -F'\t' -v V="$1" '$1 == V { printf "%s ", $3 }' "$ALL"; }
imp=$(count impacted); unk=$(count unknown); ok=$(count "not impacted"); err=$(count error); skip=$(count skipped)

echo "---"
echo "PHP criticals 2026-11-19 via kubectl exec: $n container(s): $imp impacted, $unk unknown, $ok not impacted, $err error, $skip skipped (no PHP)"
[ "$imp" -gt 0 ] && echo "  impacted:     $(names impacted)"
[ "$unk" -gt 0 ] && echo "  unknown:      $(names unknown)"
[ "$err" -gt 0 ] && echo "  error:        $(names error)"
# Tally of the detector's own per-CVE status tokens (no CVE logic here).
percve=$(cat "$WORK"/[0-9]*.txt 2>/dev/null | tr -d '\r' |
    awk '$1 ~ /^CVE-[0-9]+-[0-9]+$/ && $2 == "IMPACTED" { c[$1]++ } END { for (k in c) printf "  %s  IMPACTED in %d container(s)\n", k, c[k] }' | sort)
[ -n "$percve" ] && printf '%s\n' "$percve"
[ -n "$OUTDIR" ] && echo "per-container output in $OUTDIR/"

[ "$imp" -gt 0 ] && exit 1
{ [ "$unk" -gt 0 ] || [ "$err" -gt 0 ]; } && exit 2
if [ "$ok" -eq 0 ]; then
    echo "$PROG: every container was skipped; nothing was actually checked" >&2
    exit 2
fi
exit 0
