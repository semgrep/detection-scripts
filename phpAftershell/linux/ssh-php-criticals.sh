#!/usr/bin/env bash
# ssh-php-criticals.sh -- run the PHP-criticals (2026-11-19) host detector
# across Linux hosts over SSH and roll up the per-host verdicts.
#
# BEST-EFFORT TRIAGE AID. Read-only on targets. No warranty: a "not impacted"
# verdict is the detector's opinion of what it could see, not proof of safety.
#
# What it does
#   For each host it runs detect-php-criticals.sh (the file next to this
#   wrapper) with -q and records the detector's final verdict line plus its
#   exit code. The wrapper contains NO CVE logic; the detector is the single
#   source of truth. No agent, no install.
#     default : the detector is piped to the remote bash over stdin
#               (ssh host 'bash -s -- -q' < detector); nothing is written to
#               the target.
#     -c      : copy mode. The detector is written to a mktemp file on the
#               target, run from there with stdin closed, and removed. Use it
#               if the stdin pipe misbehaves on a target.
#
# Required access / permissions
#   - Key-based (non-interactive) SSH to every host; BatchMode is forced, so
#     hosts that would prompt for a password are reported as errors.
#   - bash 3.2+ on the targets (the detector requires bash).
#   - No root needed by default. Use -s (sudo -n, passwordless sudo) when the
#     PHP / php-fpm / web-server config on the targets is not world-readable;
#     unreadable config makes the detector answer "unknown".
#
# Per-host output
#   host: <verdict> (exit N)        verdict = impacted | not impacted | unknown
#   host: error: <reason> (exit N)  no verdict line came back (ssh/sudo/bash)
#
# Exit codes (same contract as the detector, applied to the whole fleet)
#   0  every host answered "not impacted"
#   1  at least one host is impacted
#   2  nobody impacted, but at least one host is unknown or errored
#   3  usage error / detector not found / no hosts given
set -u

PROG=${0##*/}
HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
DETECTOR=${DETECT:-$HERE/detect-php-criticals.sh}
DETECT_ARGS=${DETECT_ARGS:-}
PARALLEL=${PARALLEL:-8}
SUDO=""
COPY=0
VERBOSE=0
OUTDIR=""
HOSTS_FILE=""
SSH_USER_OPTS=()
HOSTS=()

usage() {
    cat <<EOF
Usage: $PROG [options] [host ...]
       $PROG [options] -H hosts.txt

Run detect-php-criticals.sh -q on each host over SSH and print
"host: <verdict> (exit N)" per host plus a roll-up. Best-effort triage aid,
read-only on targets, no warranty.

Hosts:
  host ...        hosts (or user@host) given as arguments
  -H FILE         hosts file: one host or user@host per line; blank lines and
                  # comments are ignored. May be combined with host arguments.

Options:
  -o SSH_OPTION   passed to ssh as "-o SSH_OPTION" (repeatable),
                  e.g. -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5
  -i IDENTITY     ssh identity file          -p PORT   ssh port
  -l USER         ssh login user             -J JUMP   ssh ProxyJump host
  -s              run the detector under "sudo -n" (passwordless sudo)
  -c              copy mode: write the detector to a mktemp file on the target,
                  run it, remove it (default: pipe over stdin, nothing written)
  -P N            hosts to check in parallel (default: $PARALLEL)
  -d DIR          keep each host's full detector output in DIR/<n>_<host>.txt
  -v              also print each host's per-CVE lines
  -h              this help

Environment:
  DETECT          path to the detector (default: next to this wrapper)
  DETECT_ARGS     extra detector arguments appended after -q (e.g. "-b /opt/php/bin/php")
  PARALLEL        same as -P

Exit codes:
  0 all not impacted   1 >=1 host impacted   2 >=1 unknown/error (none impacted)
  3 usage error, detector missing, or no hosts
EOF
}

die_usage() { echo "$PROG: $*" >&2; echo "Try '$PROG -h' for usage." >&2; exit 3; }
need_val() { [ "$2" -ge 2 ] || die_usage "option $1 needs a value"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -H) need_val "$1" $#; HOSTS_FILE=$2; shift ;;
        -o) need_val "$1" $#; SSH_USER_OPTS+=(-o "$2"); shift ;;
        -i) need_val "$1" $#; SSH_USER_OPTS+=(-i "$2"); shift ;;
        -p) need_val "$1" $#; SSH_USER_OPTS+=(-p "$2"); shift ;;
        -l) need_val "$1" $#; SSH_USER_OPTS+=(-l "$2"); shift ;;
        -J) need_val "$1" $#; SSH_USER_OPTS+=(-J "$2"); shift ;;
        -P) need_val "$1" $#; PARALLEL=$2; shift ;;
        -d) need_val "$1" $#; OUTDIR=$2; shift ;;
        -s) SUDO="sudo -n" ;;
        -c) COPY=1 ;;
        -v) VERBOSE=1 ;;
        --) shift; while [ $# -gt 0 ]; do HOSTS+=("$1"); shift; done; break ;;
        -*) die_usage "unknown option: $1" ;;
        *)  HOSTS+=("$1") ;;
    esac
    shift
done

case "$PARALLEL" in ''|*[!0-9]*|0) die_usage "-P needs a positive integer" ;; esac

if [ -n "$HOSTS_FILE" ]; then
    [ -f "$HOSTS_FILE" ] || die_usage "hosts file not found: $HOSTS_FILE"
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%%#*}
        # shellcheck disable=SC2086
        set -- $line
        [ $# -ge 1 ] || continue
        HOSTS+=("$1")
    done < <(tr -d '\r' < "$HOSTS_FILE")
fi

[ "${#HOSTS[@]}" -gt 0 ] || die_usage "no hosts given (pass hosts as arguments or use -H hosts.txt)"
[ -f "$DETECTOR" ] || { echo "$PROG: detector not found at $DETECTOR (set DETECT=/path/to/detect-php-criticals.sh)" >&2; exit 3; }
command -v ssh >/dev/null 2>&1 || { echo "$PROG: ssh not found in PATH" >&2; exit 3; }

if [ -n "$OUTDIR" ]; then
    mkdir -p "$OUTDIR" || exit 3
    WORK=$OUTDIR
    rm -f "$WORK"/.status.* 2>/dev/null
    trap 'rm -f "$WORK"/.status.* "$WORK"/.detector.sh 2>/dev/null' EXIT
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/phpcrit-ssh.XXXXXX") || exit 3
    trap 'rm -rf "$WORK"' EXIT
fi

# Transport hygiene only: send an LF-only copy so a CRLF checkout of the
# detector (e.g. on a Windows control node) still runs under the remote bash.
PAYLOAD=$WORK/.detector.sh
tr -d '\r' < "$DETECTOR" > "$PAYLOAD" || exit 3

if [ "$COPY" = 1 ]; then
    REMOTE="f=\$(mktemp \"\${TMPDIR:-/tmp}/phpcrit.XXXXXX\") || exit 97; cat >\"\$f\" || { rm -f \"\$f\"; exit 97; }; $SUDO bash \"\$f\" -q $DETECT_ARGS </dev/null; rc=\$?; rm -f \"\$f\"; exit \$rc"
else
    REMOTE="$SUDO bash -s -- -q $DETECT_ARGS"
fi

safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._@-' '_'; }
last_line() { tr -d '\r' < "$1" | awk 'NF { l = $0 } END { print l }'; }

# classify LAST_LINE RC -> impacted | not impacted | unknown | error
# A verdict needs the detector's final verdict line; an exit code alone is not
# trusted (sudo/ssh/bash failures also exit 1/2). If line and code disagree the
# worse of the two wins.
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
    idx=$1; h=$2
    f="$WORK/${idx}_$(safe "$h").txt"
    case "$h" in
        -*) rc=3; : > "$f"; echo "host name starts with '-'" > "$f.err" ;;
        *)
            ssh ${SSH_USER_OPTS[@]+"${SSH_USER_OPTS[@]}"} \
                -o BatchMode=yes -o ConnectTimeout=15 \
                -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
                -- "$h" "$REMOTE" < "$PAYLOAD" > "$f" 2> "$f.err"
            rc=$?
            ;;
    esac
    line=$(last_line "$f")
    class=$(classify "$line" "$rc")
    detail=""
    if [ "$class" = error ]; then
        case "$rc" in
            255) detail="ssh/connection failure" ;;
            126|127) detail="bash (or sudo) not runnable on target" ;;
            97) detail="could not create temp file on target" ;;
            3) detail="detector usage error" ;;
            *) detail="no verdict line from detector" ;;
        esac
        e=$(tr -d '\r' < "$f.err" 2>/dev/null | awk 'NF { l = $0 } END { print substr(l, 1, 120) }')
        [ -n "$e" ] && detail="$detail: $e"
        msg="$h: error: $detail (exit $rc)"
    elif [ "$class" != "$line" ]; then
        msg="$h: $class (exit $rc; verdict line was \"$line\")"
    else
        msg="$h: $class (exit $rc)"
    fi
    if [ "$VERBOSE" = 1 ]; then
        cves=$(tr -d '\r' < "$f" | awk '$1 ~ /^CVE-[0-9]+-[0-9]+$/ { print "    " $0 }')
        [ -n "$cves" ] && msg="$msg
$cves"
    fi
    printf '%s\n' "$msg"
    printf '%s\t%s\t%s\n' "$class" "$rc" "$h" > "$WORK/.status.$idx"
    [ -s "$f.err" ] || rm -f "$f.err"
}

n=0
for h in "${HOSTS[@]}"; do
    n=$((n + 1))
    one "$(printf '%04d' "$n")" "$h" &
    [ $((n % PARALLEL)) -eq 0 ] && wait
done
wait

ALL=$WORK/.status.all
cat "$WORK"/.status.[0-9]* > "$ALL" 2>/dev/null
count() { awk -F'\t' -v V="$1" '$1 == V { c++ } END { print c + 0 }' "$ALL"; }
names() { awk -F'\t' -v V="$1" '$1 == V { printf "%s ", $3 }' "$ALL"; }
imp=$(count impacted); unk=$(count unknown); ok=$(count "not impacted"); err=$(count error)

echo "---"
echo "PHP criticals 2026-11-19 via SSH: $n host(s): $imp impacted, $unk unknown, $ok not impacted, $err error"
[ "$imp" -gt 0 ] && echo "  impacted:     $(names impacted)"
[ "$unk" -gt 0 ] && echo "  unknown:      $(names unknown)"
[ "$err" -gt 0 ] && echo "  error:        $(names error)"
# Tally of the detector's own per-CVE status tokens (no CVE logic here).
percve=$(cat "$WORK"/[0-9]*.txt 2>/dev/null | tr -d '\r' |
    awk '$1 ~ /^CVE-[0-9]+-[0-9]+$/ && $2 == "IMPACTED" { c[$1]++ } END { for (k in c) printf "  %s  IMPACTED on %d host(s)\n", k, c[k] }' | sort)
[ -n "$percve" ] && printf '%s\n' "$percve"
[ -n "$OUTDIR" ] && echo "per-host output in $OUTDIR/"

[ "$imp" -gt 0 ] && exit 1
{ [ "$unk" -gt 0 ] || [ "$err" -gt 0 ]; } && exit 2
exit 0
