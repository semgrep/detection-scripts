#!/usr/bin/env bash
# azure-runcommand-php-criticals.sh -- run the PHP-criticals (2026-11-19) host
# detector on Azure Linux VMs via `az vm run-command invoke` and roll up the
# per-VM verdicts.
#
# BEST-EFFORT TRIAGE AID. Read-only on targets. No warranty: a "not impacted"
# verdict is the detector's opinion of what it could see, not proof of safety.
#
# What it does
#   For each running Linux VM it sends a small generated script through Azure
#   Run Command (RunShellScript; synchronous, no SSH, no install). That script
#   carries detect-php-criticals.sh (the file next to this wrapper) verbatim,
#   writes it to a mktemp file on the VM, runs it with -q, removes the temp
#   file, and prints a "PHPCRIT_EXIT=<n>" marker, because Run Command returns
#   only stdout/stderr and not the script's exit code. The wrapper contains NO
#   CVE logic; the detector is the single source of truth. Nothing else is
#   changed on the VM (the VM agent itself stages the Run Command script under
#   /var/lib/waagent, as it does for every Run Command).
#
# Required access / permissions
#   - Azure CLI (`az`), logged in (`az login`), and `jq` on this machine.
#   - Microsoft.Compute/virtualMachines/read and .../runCommand/action on the
#     targets (e.g. the built-in "Virtual Machine Contributor" role).
#   - The Azure VM agent running on each VM; bash present on the VM.
#   - Run Command executes as root on the VM. One Run Command at a time per VM;
#     each call typically takes 20-60 s.
#
# Per-VM output
#   rg/vm: <verdict> (exit N)        verdict = impacted | not impacted | unknown
#   rg/vm: skipped (<reason>)        not Linux / not running
#   rg/vm: error: <reason> (exit N)  no verdict came back
#
# Exit codes
#   0  every checked VM answered "not impacted"
#   1  at least one VM is impacted
#   2  nobody impacted, but at least one unknown/error, or no VMs matched
#   3  usage error / detector, az or jq not found / VM listing failed
set -u

PROG=${0##*/}
HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
DETECTOR=${DETECT:-$HERE/detect-php-criticals.sh}
DETECT_ARGS=${DETECT_ARGS:-}
PARALLEL=${PARALLEL:-5}
RG=""; SUBSCRIPTION=""; NAMES=""; VERBOSE=0; OUTDIR=""
EOF_MARK=PHPCRIT_DETECTOR_PAYLOAD_EOF

usage() {
    cat <<EOF
Usage: $PROG -g RESOURCE_GROUP [options]
       $PROG --all-resource-groups [options]

Run detect-php-criticals.sh -q on Azure Linux VMs with
"az vm run-command invoke" and print "rg/vm: <verdict> (exit N)" per VM plus a
roll-up. Best-effort triage aid, read-only on targets, no warranty.

Selection:
  -g RG                    resource group to check
  --all-resource-groups    every VM in the subscription (instead of -g)
  -n VM                    only this VM name (repeatable)
  -s SUBSCRIPTION          subscription name or id (default: az's current one)

Options:
  -P N            VMs to check in parallel (default: $PARALLEL)
  -d DIR          keep each VM's full Run Command output in DIR/
  -v              also print each VM's per-CVE lines
  -h              this help

Environment:
  DETECT          path to the detector (default: next to this wrapper)
  DETECT_ARGS     extra detector arguments appended after -q
  PARALLEL        same as -P

Needs: az (logged in) and jq; "Virtual Machine Contributor" (or
virtualMachines/read + runCommand/action) on the targets; VM agent running.

Exit codes:
  0 all not impacted   1 >=1 VM impacted
  2 >=1 unknown/error (none impacted), or no VMs matched
  3 usage error, detector/az/jq missing, or VM listing failed
EOF
}

die_usage() { echo "$PROG: $*" >&2; echo "Try '$PROG -h' for usage." >&2; exit 3; }
need_val() { [ "$2" -ge 2 ] || die_usage "option $1 needs a value"; }

ALL_RG=0
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -g|--resource-group) need_val "$1" $#; RG=$2; shift ;;
        --all-resource-groups) ALL_RG=1 ;;
        -n|--name) need_val "$1" $#; NAMES="${NAMES:+$NAMES,}$2"; shift ;;
        -s|--subscription) need_val "$1" $#; SUBSCRIPTION=$2; shift ;;
        -P) need_val "$1" $#; PARALLEL=$2; shift ;;
        -d) need_val "$1" $#; OUTDIR=$2; shift ;;
        -v) VERBOSE=1 ;;
        *) die_usage "unknown argument: $1" ;;
    esac
    shift
done

case "$PARALLEL" in ''|*[!0-9]*|0) die_usage "-P needs a positive integer" ;; esac
[ -n "$RG" ] && [ "$ALL_RG" = 1 ] && die_usage "use either -g RG or --all-resource-groups, not both"
[ -n "$RG" ] || [ "$ALL_RG" = 1 ] || die_usage "no targets: specify -g RESOURCE_GROUP (or --all-resource-groups)"
[ -f "$DETECTOR" ] || { echo "$PROG: detector not found at $DETECTOR (set DETECT=/path/to/detect-php-criticals.sh)" >&2; exit 3; }
command -v az >/dev/null 2>&1 || { echo "$PROG: az (Azure CLI) not found in PATH" >&2; exit 3; }
command -v jq >/dev/null 2>&1 || { echo "$PROG: jq not found in PATH" >&2; exit 3; }
if grep -q "^$EOF_MARK" "$DETECTOR"; then
    echo "$PROG: detector contains the reserved line $EOF_MARK; cannot embed it" >&2; exit 3
fi

if [ -n "$OUTDIR" ]; then
    mkdir -p "$OUTDIR" || exit 3
    WORK=$OUTDIR
    rm -f "$WORK"/.status.* 2>/dev/null
    trap 'rm -f "$WORK"/.status.* "$WORK"/.vms.tsv "$WORK"/.vms.err "$WORK"/.payload.sh 2>/dev/null' EXIT
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/phpcrit-az.XXXXXX") || exit 3
    trap 'rm -rf "$WORK"' EXIT
fi

# The script Run Command executes on the VM: detector embedded verbatim
# (LF-only), written to a temp file, run with -q, temp file removed, exit code
# echoed as the last stdout line.
PAYLOAD=$WORK/.payload.sh
{
    cat <<'HEAD'
#!/bin/sh
# Generated by azure-runcommand-php-criticals.sh; read-only triage.
f=$(mktemp "${TMPDIR:-/tmp}/phpcrit.XXXXXX") || { echo "PHPCRIT_EXIT=97"; exit 0; }
HEAD
    printf "cat > \"\$f\" <<'%s'\n" "$EOF_MARK"
    tr -d '\r' < "$DETECTOR"
    printf '\n%s\n' "$EOF_MARK"
    printf 'if command -v bash >/dev/null 2>&1; then bash "$f" -q %s </dev/null; rc=$?; else echo "bash not found on VM" >&2; rc=127; fi\n' "$DETECT_ARGS"
    cat <<'TAIL'
rm -f "$f"
echo "PHPCRIT_EXIT=$rc"
TAIL
} > "$PAYLOAD" || exit 3

# az on Windows is a native program: hand it a Windows path when under Git Bash.
PAYLOAD_ARG=$PAYLOAD
if command -v cygpath >/dev/null 2>&1; then PAYLOAD_ARG=$(cygpath -w "$PAYLOAD"); fi

AZ_COMMON=()
[ -n "$SUBSCRIPTION" ] && AZ_COMMON+=(--subscription "$SUBSCRIPTION")
LIST_ARGS=(-d -o json)
[ -n "$RG" ] && LIST_ARGS+=(-g "$RG")

# rg <TAB> name <TAB> osType <TAB> powerState
az vm list "${LIST_ARGS[@]}" ${AZ_COMMON[@]+"${AZ_COMMON[@]}"} 2>"$WORK/.vms.err" |
    jq -r --arg names "$NAMES" '
        ($names | split(",") | map(select(length > 0))) as $want
        | .[]
        | select(($want | length) == 0 or (.name as $n | $want | index($n) != null))
        | [.resourceGroup, .name, (.storageProfile.osDisk.osType // "unknown"), (.powerState // "unknown")]
        | @tsv' | tr -d '\r' > "$WORK/.vms.tsv"
if [ "${PIPESTATUS[0]}" != 0 ]; then
    echo "$PROG: az vm list failed: $(tail -n 1 "$WORK/.vms.err" 2>/dev/null)" >&2
    exit 3
fi

safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._@-' '_'; }

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

one() {
    idx=$1; rg=$2; vm=$3
    t="$rg/$vm"
    f="$WORK/${idx}_$(safe "$rg.$vm").txt"
    az vm run-command invoke -g "$rg" -n "$vm" ${AZ_COMMON[@]+"${AZ_COMMON[@]}"} \
        --command-id RunShellScript --scripts "@$PAYLOAD_ARG" -o json 2>"$f.err" |
        jq -r '.value[0].message // empty' 2>/dev/null | tr -d '\r' > "$f.msg"
    azrc=${PIPESTATUS[0]}
    # Run Command message layout: "Enable succeeded: \n[stdout]\n...\n[stderr]\n..."
    awk '$0 == "[stderr]" { s = 0 } s { print } $0 == "[stdout]" { s = 1 }' "$f.msg" > "$f"
    rc=$(sed -n 's/^PHPCRIT_EXIT=\([0-9][0-9]*\)$/\1/p' "$f" | tail -n 1)
    line=$(awk '/^PHPCRIT_EXIT=/ { next } NF { l = $0 } END { print l }' "$f")
    if [ -z "$rc" ]; then
        class=error; rc="-"
        e=$(tr -d '\r' < "$f.err" | awk 'NF { l = $0 } END { print substr(l, 1, 160) }')
        detail="run-command returned no result (az exit $azrc)${e:+: $e}"
    else
        class=$(classify "$line" "$rc")
        case "$rc" in
            127) detail="bash not found on VM" ;;
            97) detail="could not create temp file on VM" ;;
            *) detail="no verdict line from detector" ;;
        esac
    fi
    if [ "$class" = error ]; then
        msg="$t: error: $detail (exit $rc)"
    elif [ "$class" != "$line" ]; then
        msg="$t: $class (exit $rc; verdict line was \"$line\")"
    else
        msg="$t: $class (exit $rc)"
    fi
    if [ "$VERBOSE" = 1 ]; then
        cves=$(awk '$1 ~ /^CVE-[0-9]+-[0-9]+$/ { print "    " $0 }' "$f")
        [ -n "$cves" ] && msg="$msg
$cves"
    fi
    printf '%s\n' "$msg"
    printf '%s\t%s\t%s\n' "$class" "$rc" "$t" > "$WORK/.status.$idx"
    if [ -n "$OUTDIR" ]; then mv -f "$f.msg" "$f" 2>/dev/null; else rm -f "$f.msg"; fi
    [ -s "$f.err" ] || rm -f "$f.err"
}

n=0; running=0
while IFS=$'\t' read -r rg vm os power <&3; do
    [ -n "$rg" ] && [ -n "$vm" ] || continue
    n=$((n + 1))
    idx=$(printf '%04d' "$n")
    if [ "$os" != Linux ]; then
        echo "$rg/$vm: skipped (osType $os; this wrapper is Linux-only)"
        printf 'skipped\t-\t%s\n' "$rg/$vm" > "$WORK/.status.$idx"
    elif [ "$power" != "VM running" ]; then
        echo "$rg/$vm: skipped (power state: $power)"
        printf 'skipped\t-\t%s\n' "$rg/$vm" > "$WORK/.status.$idx"
    else
        running=$((running + 1))
        one "$idx" "$rg" "$vm" &
        [ $((running % PARALLEL)) -eq 0 ] && wait
    fi
done 3< "$WORK/.vms.tsv"
wait

# VMs asked for by name (-n) that the listing did not return.
if [ -n "$NAMES" ]; then
    OLDIFS=$IFS; IFS=,
    for want in $NAMES; do
        IFS=$OLDIFS
        if ! awk -F'\t' -v V="$want" '$2 == V { f = 1 } END { exit !f }' "$WORK/.vms.tsv"; then
            n=$((n + 1))
            echo "${RG:-*}/$want: error: VM not found (exit -)"
            printf 'error\t-\t%s\n' "${RG:-*}/$want" > "$WORK/.status.$(printf '%04d' "$n")"
        fi
        IFS=,
    done
    IFS=$OLDIFS
fi

if [ "$n" -eq 0 ]; then
    echo "$PROG: no VMs matched the selection; nothing checked" >&2
    exit 2
fi

ALL=$WORK/.status.all
cat "$WORK"/.status.[0-9]* > "$ALL" 2>/dev/null
count() { awk -F'\t' -v V="$1" '$1 == V { c++ } END { print c + 0 }' "$ALL"; }
names() { awk -F'\t' -v V="$1" '$1 == V { printf "%s ", $3 }' "$ALL"; }
imp=$(count impacted); unk=$(count unknown); ok=$(count "not impacted"); err=$(count error); skip=$(count skipped)

echo "---"
echo "PHP criticals 2026-11-19 via Azure Run Command: $n VM(s): $imp impacted, $unk unknown, $ok not impacted, $err error, $skip skipped"
[ "$imp" -gt 0 ] && echo "  impacted:     $(names impacted)"
[ "$unk" -gt 0 ] && echo "  unknown:      $(names unknown)"
[ "$err" -gt 0 ] && echo "  error:        $(names error)"
[ "$skip" -gt 0 ] && echo "  skipped:      $(names skipped)"
# Tally of the detector's own per-CVE status tokens (no CVE logic here).
percve=$(cat "$WORK"/[0-9]*.txt 2>/dev/null | tr -d '\r' |
    awk '$1 ~ /^CVE-[0-9]+-[0-9]+$/ && $2 == "IMPACTED" { c[$1]++ } END { for (k in c) printf "  %s  IMPACTED on %d VM(s)\n", k, c[k] }' | sort)
[ -n "$percve" ] && printf '%s\n' "$percve"
[ -n "$OUTDIR" ] && echo "per-VM output in $OUTDIR/"

[ "$imp" -gt 0 ] && exit 1
{ [ "$unk" -gt 0 ] || [ "$err" -gt 0 ]; } && exit 2
if [ "$ok" -eq 0 ]; then
    echo "$PROG: every VM was skipped; nothing was actually checked" >&2
    exit 2
fi
exit 0
