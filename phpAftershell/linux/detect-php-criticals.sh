#!/usr/bin/env bash
#
# detect-php-criticals.sh
#
# Checks this host against all seven CRITICAL (CVSS v4.0 9.2) issues fixed by
# the PHP security release of 2026-11-19 (8.5.13 / 8.4.28 / 8.3.37 / 8.2.36)
# and prints one status line per CVE. It is the single-file, fleet-deployable
# sum of the seven per-CVE detectors in ../../CVE-2026-*/linux/ and applies
# the same gates:
#
#   CVE-2026-129289  FPM request smuggling            8.2-8.5 (EOL >= 5.6 too)
#       php-fpm below the fix AND the front end reuses FastCGI connections
#       (nginx "fastcgi_keep_conn on", Apache "enablereuse=on", HAProxy
#       fcgi-app). Front end not inspectable -> UNKNOWN, never guessed. A host
#       with no php-fpm at all is NOT_IMPACTED. The application half (a route
#       that does not read the request body) is assumed, not checked.
#   CVE-2026-115560  Session serializer mismatch      8.2-8.5
#       below the fix AND session.upload_progress.enabled on. With
#       serialize_handler php_serialize / php_binary the config precondition
#       is MET; with the default "php" handler it is NOT RULED OUT (runtime
#       ini_set or another pool can supply the mismatch). Upload progress off
#       clears it only for a php-fpm ini with no override; on a CLI ini that
#       is UNKNOWN.
#   CVE-2026-129496  Date timezone-cache UAF          8.2-8.5, NTS builds
#       below the fix AND NTS (or threading unknown) AND PHP's error_log ini
#       names a FILE, in the binary's ini or in a web-side ini / pool / Apache
#       override. ZTS -> NOT_IMPACTED. php-fpm with error_log unset / syslog
#       and no web-side file log -> NOT_IMPACTED; the same on a CLI ini is
#       UNKNOWN. FPM's own log (php-fpm.conf [global] error_log) does not count.
#   CVE-2026-126714  Session partial file overwrite   8.2-8.5 (EOL: no)
#       "phpAfterShell": the files save handler rewrites the session file in
#       place (non-atomic pwrite + ftruncate) for an upload-progress update.
#       No application gadget chain and no session_start() are needed.
#       below the fix AND session.save_handler = files AND
#       session.upload_progress.enabled on (both defaults) -> IMPACTED.
#       files + upload progress off -> UNKNOWN (demonstrated vector removed,
#       but the advisory says the class is not limited to upload progress).
#       Another handler clears it only for a php-fpm ini with no override of
#       session.save_handler (pool / vhost / .htaccess / .user.ini /
#       ini_set); otherwise, or with the handler unreadable, UNKNOWN.
#       8.1 and older: only the official EOL mitigation branches are not
#       vulnerable; older unpatched 7.4 / 8.0 / 8.1 builds are, and the
#       version number does not show which -> UNKNOWN, or NOT_IMPACTED when
#       the operator sets PHP2026_EOL_MITIGATED=1 (this CVE only).
#   CVE-2026-129481  Session UAF interrupted shutdown 8.3-8.5 (8.2: n/a)
#       no ini gate: an unpatched 8.3-8.5 is IMPACTED because the application
#       pattern cannot be ruled out from the host. Code hints with
#       PHP2026_APP_PATH.
#   CVE-2026-129474  Magic-method backtrace UAF       8.5 only
#       8.5 below the fix AND zend.exception_ignore_args=0 AND
#       fatal_error_backtraces != 0 (the compiled-in 8.5 defaults; the
#       php.ini-production value zend.exception_ignore_args=1 closes it). A
#       pool / vhost / .htaccess / .user.ini / ini_set() line that turns
#       zend.exception_ignore_args off also counts.
#   CVE-2026-129182  last_fatal_error_backtrace UAF   8.5 only
#       8.5 below the fix AND at least one per-directory / per-request INI
#       override found (Apache php_value & co., .htaccess, PHP_VALUE /
#       PHP_ADMIN_VALUE from the front end). None found -> UNKNOWN: an empty
#       scan does not prove absence.
#
# Status tokens, one line per CVE ("CVE-2026-NNNNNN  TOKEN  short name"):
#   IMPACTED        version below the fix AND the CVE's precondition is met
#                   or cannot be ruled out on this host
#   NOT_IMPACTED    patched, or the precondition is ruled out
#   UNKNOWN         cannot decide: no PHP found, unparseable version,
#                   end-of-life / unlisted / pre-release series, a web runtime
#                   that cannot be queried (mod_php, FrankenPHP), or a
#                   precondition ruled out only in a CLI ini
#   NOT_APPLICABLE  the PHP series on this host is not in the CVE's branch
#                   list (129474 / 129182 off 8.5; 129481 on 8.2)
# With several PHP installs the per-CVE status is the worst one:
# IMPACTED > UNKNOWN > NOT_IMPACTED > NOT_APPLICABLE.
#
# Version gate: MAJOR.MINOR series listed in the fixed-in list and PATCH lower
# than the fixed PATCH -> below the fix. PATCH >= fixed -> patched. RC / alpha
# / beta / -dev at or above the fixed PATCH -> UNKNOWN. 8.1 and older are
# end-of-life and get no fix: UNKNOWN (treat as exposed), except 129289, whose
# bug exists since 5.6.0 and is evaluated on them. For 126714 an official EOL
# mitigation exists; see its paragraph above. Distribution packages may
# carry the fix as a backport without a change of the upstream version; such
# installs are still reported by version.
#
# IMPORTANT - CLI ini is not web ini. "php -i" shows the CLI configuration.
# The web SAPI (php-fpm, mod_php, FrankenPHP) loads its own php.ini and adds
# per-pool php_value / php_admin_value, .htaccess php_value, .user.ini and
# fastcgi_param PHP_VALUE on top. A php-fpm binary is queried with its own
# "-i"; pool, vhost and per-directory overrides are searched for and can block
# a NOT_IMPACTED or open a gate, but they are never merged into an install's
# values. A clean result from a CLI row says nothing about the web SAPI.
#
# What gets checked (gathered once, then every gate is evaluated on it):
#   - php, phpN.N, php-fpm, php-fpmN.N, php-cgi on PATH and in common install
#     directories (/usr/bin, /usr/sbin, /usr/local, /opt/*/bin, Homebrew,
#     Remi, Plesk, cPanel EA, CloudLinux alt-php); the binary of every running
#     php-fpm master (Linux, via /proc); any binary passed with -b
#   - "<php> -v" and "<php> -i" of each: version, SAPI, thread safety, ini
#   - php-fpm pool files, web-side php.ini files, nginx / Apache / HAProxy /
#     Caddy / lighttpd / OpenLiteSpeed config, plus PHP2026_WEB_CONF_DIRS
#   - .htaccess and .user.ini under /var/www, /srv/www, /srv/http,
#     /usr/share/nginx/html, /usr/local/www, /home/*/public_html (6 levels)
#     and all of PHP2026_APP_PATH; PHP sources under PHP2026_APP_PATH
#   - mod_php (libphp*.so) and FrankenPHP: detected, cannot be queried, and
#     therefore reported UNKNOWN for the CVEs they could carry
#
# Not checked: PHP inside containers (run this script in the container; see
# the k8s wrappers), statically embedded PHP, php-cgi ini (its -i prints
# HTML), front ends on other hosts, the application-side halves of the
# preconditions (gadget chains, unread request bodies, magic methods),
# Windows.
#
# This script is read-only: it runs "<php> -v" and "<php> -i", reads config
# files, the tail of the PHP error log and /proc, makes no network calls,
# sends no requests to any server, and writes nothing but stdout (usage
# errors go to stderr). It contains no exploit code.
#
# Exit codes, for fleet tooling:
#   0  not impacted: no CVE is IMPACTED or UNKNOWN
#   1  impacted: at least one CVE is IMPACTED
#   2  unknown: none impacted, but at least one UNKNOWN (or no PHP found)
#   3  usage error
#
# The last line of stdout is always exactly one of:
#   impacted | not impacted | unknown
#
# Works with bash 3.2 (macOS) and later. Run as root for full coverage of
# other users' processes, root-only config files and log files.

set -u

# Versions that contain the fix, one per MAJOR.MINOR series, space separated.
FIXED_IN="${PHPCRIT_FIXED_IN:-8.2.36 8.3.37 8.4.28 8.5.13}"
# Optional application tree / web root: .htaccess, .user.ini and PHP sources.
APP_PATH="${PHP2026_APP_PATH:-}"
# Optional extra web-server config directories or files, colon separated.
WEB_CONF_EXTRA="${PHP2026_WEB_CONF_DIRS:-}"
PROBE_TIMEOUT="${PHPCRIT_PROBE_TIMEOUT:-20}"

QUIET=0
VERBOSE=0
JSON=0
EXTRA_BINS=""
NL='
'
TAB=$(printf '\t')

usage() {
    printf '%s\n' \
'usage: detect-php-criticals.sh [-q] [-v] [--json] [-b /path/to/php]...' \
'' \
'  -q, --quiet     print only the per-CVE lines and the final verdict' \
'  -v, --verbose   add the gate findings and the mitigation under each CVE' \
'  -b, --php PATH  also check this php / php-fpm binary (repeatable)' \
'      --json      print one JSON object (line 1) instead of the report; the' \
'                  verdict word is still the last line' \
'  -h, --help      show this help' \
'' \
'Output: one line per CVE, "CVE-2026-NNNNNN  STATUS  short name", STATUS one of' \
'        IMPACTED | NOT_IMPACTED | UNKNOWN | NOT_APPLICABLE; then "overall: ..."' \
'        and a last line that is exactly: impacted | not impacted | unknown' \
'Exit:   0 none impacted, 1 at least one CVE impacted, 2 unknown / no PHP found,' \
'        3 usage error.' \
'Env:    PHPCRIT_FIXED_IN="8.2.36 8.3.37 8.4.28 8.5.13"  fixed version per series' \
'        PHP2026_APP_PATH=/var/www/app     web root / source tree to scan' \
'        PHP2026_WEB_CONF_DIRS=/a:/b       extra web-server config paths' \
'        PHPCRIT_PROBE_TIMEOUT=20          seconds allowed per php invocation' \
'' \
'NOTE: "php -i" shows the CLI ini, not the web SAPI ini. Run as root, and read' \
'      the php-fpm rows; audit mod_php / FrankenPHP / containers separately.'
}

while [ $# -gt 0 ]; do
    case "$1" in
        -q|--quiet) QUIET=1 ;;
        -v|--verbose) VERBOSE=1 ;;
        --json) JSON=1 ;;
        -b|--php)
            [ $# -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 3; }
            EXTRA_BINS="$EXTRA_BINS$2$NL"
            shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 3 ;;
    esac
    shift
done

is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ ${#1} -le 9 ]
}

# FIXED_IN must be plain MAJOR.MINOR.PATCH entries, one per series.
FIXED_SERIES=""
FIXED_CLEAN=""
FIXED_85_PAT=13
for f in $FIXED_IN; do
    f_maj=${f%%.*}; f_rest=${f#*.}; f_min=${f_rest%%.*}; f_pat=${f_rest#*.}
    case "$f" in
        *.*.*) : ;;
        *) echo "PHPCRIT_FIXED_IN: bad entry '$f' (want MAJOR.MINOR.PATCH)" >&2; exit 3 ;;
    esac
    if ! is_uint "$f_maj" || ! is_uint "$f_min" || ! is_uint "$f_pat"; then
        echo "PHPCRIT_FIXED_IN: bad entry '$f' (want MAJOR.MINOR.PATCH)" >&2
        exit 3
    fi
    f_maj=$((10#$f_maj)); f_min=$((10#$f_min)); f_pat=$((10#$f_pat))
    case " $FIXED_SERIES " in
        *" $f_maj.$f_min "*)
            echo "PHPCRIT_FIXED_IN: series $f_maj.$f_min listed more than once" >&2
            exit 3 ;;
    esac
    FIXED_SERIES="$FIXED_SERIES $f_maj.$f_min"
    FIXED_CLEAN="$FIXED_CLEAN $f_maj.$f_min.$f_pat"
    [ "$f_maj.$f_min" = "8.5" ] && FIXED_85_PAT=$f_pat
done
FIXED_IN=${FIXED_CLEAN# }
if [ -z "$FIXED_IN" ]; then
    echo "PHPCRIT_FIXED_IN: no fixed versions given" >&2
    exit 3
fi
FIXED_85="8.5.$FIXED_85_PAT"
is_uint "$PROBE_TIMEOUT" || PROBE_TIMEOUT=20

TO=""
if command -v timeout >/dev/null 2>&1; then
    TO="timeout $PROBE_TIMEOUT"
elif command -v gtimeout >/dev/null 2>&1; then
    TO="gtimeout $PROBE_TIMEOUT"
fi

# ------------------------------------------------------------ CVE registry

cve_id() {
    case "$1" in
        1) echo "CVE-2026-129289" ;; 2) echo "CVE-2026-115560" ;;
        3) echo "CVE-2026-129496" ;; 4) echo "CVE-2026-126714" ;;
        5) echo "CVE-2026-129481" ;; 6) echo "CVE-2026-129474" ;;
        7) echo "CVE-2026-129182" ;;
    esac
}
cve_name() {
    case "$1" in
        1) echo "FPM request smuggling" ;;
        2) echo "Session serializer mismatch" ;;
        3) echo "Date timezone-cache UAF" ;;
        4) echo "Session partial file overwrite" ;;
        5) echo "Session UAF interrupted shutdown" ;;
        6) echo "Magic-method backtrace UAF" ;;
        7) echo "last_fatal_error_backtrace UAF" ;;
    esac
}
cve_fix() {
    case "$1" in
        1) echo "update PHP and restart php-fpm; until then disable FastCGI connection reuse (nginx: remove 'fastcgi_keep_conn on;', Apache: remove enablereuse=on, HAProxy: 'no option keep-conn' / 'no option mpxs-conns')" ;;
        2) echo "PUBLIC PoC reported 2026-11-19 (prioritize). update PHP; until then session.upload_progress.enabled=0, one session.serialize_handler for every reader and writer of a session store, set in php.ini / php_admin_value and never with ini_set() (still required after patching if upload progress is explicitly enabled)" ;;
        3) echo "update PHP; until then fix every startup diagnostic (valid date.timezone, no failing extension= lines) and send PHP errors to syslog (error_log = syslog) or leave error_log unset" ;;
        4) echo "update PHP; until then session.upload_progress.enabled=0 in the web SAPI ini (vendor temporary mitigation: removes the demonstrated vector; the advisory says the issue class is not limited to upload progress, so it is not a fix)" ;;
        5) echo "update PHP (no configuration workaround); review custom session handlers and do not keep resources (streams, sockets) in \$_SESSION" ;;
        6) echo "update to PHP $FIXED_85; until then zend.exception_ignore_args=1 (the php.ini-production value) or fatal_error_backtraces=0 in the web SAPI ini, then restart the workers" ;;
        7) echo "update to PHP $FIXED_85 (the only complete fix); advisory temporary workaround: set fatal_error_backtraces=0 administratively so request-specific config cannot re-enable it, then restart all workers; also remove conflicting per-directory / per-request INI overrides (max_memory_limit / memory_limit, zlib.output_compression vs output_handler) and do not let untrusted users write .htaccess" ;;
    esac
}

ST_1=""; ST_2=""; ST_3=""; ST_4=""; ST_5=""; ST_6=""; ST_7=""
FIND_1=""; FIND_2=""; FIND_3=""; FIND_4=""; FIND_5=""; FIND_6=""; FIND_7=""

rank() {
    case "$1" in
        IMPACTED) RANK=3 ;;
        UNKNOWN) RANK=2 ;;
        NOT_IMPACTED) RANK=1 ;;
        NOT_APPLICABLE) RANK=0 ;;
        *) RANK=-1 ;;
    esac
}

# Record one install's (or one host-level) result for a CVE. The per-CVE
# status is the worst one recorded.
contrib() {  # cve-index status finding
    eval "cb_cur=\$ST_$1"
    rank "$cb_cur"; cb_r=$RANK
    rank "$2"
    [ "$RANK" -gt "$cb_r" ] && eval "ST_$1=\$2"
    [ -n "${3:-}" ] && eval "FIND_$1=\"\${FIND_$1}[\$2] \$3\$NL\""
    return 0
}
cnote() {  # cve-index text   (finding that does not change the status)
    eval "FIND_$1=\"\${FIND_$1}[info] \$2\$NL\""
}
contrib_all() {  # status finding
    for ca_i in 1 2 3 4 5 6 7; do contrib "$ca_i" "$1" "$2"; done
}

say() { [ "$QUIET" -eq 1 ] || [ "$JSON" -eq 1 ] || printf '%s\n' "$*"; }
vsay() { [ "$QUIET" -eq 0 ] && [ "$JSON" -eq 0 ] && [ "$VERBOSE" -eq 1 ] && printf '%s\n' "$*"; return 0; }

arow() {  # label text  (advisory line)
    say "$(printf '  %-4s %-26s %s' "[?]" "$1" "$2")"
}

irow() {  # label version sapi threading gate-column
    say "$(printf '  %-34s %-12s %-9s %-4s %s' "$1" "$2" "$3" "$4" "$5" | sed 's/[[:space:]]*$//')"
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

count_lines() {
    if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi
}

json_esc() { printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# Run a php binary with a time limit and no stdin. probe drops stderr;
# probe_all keeps it (startup diagnostics are printed there).
probe() {
    if [ -n "$TO" ]; then
        $TO "$@" </dev/null 2>/dev/null
    else
        "$@" </dev/null 2>/dev/null
    fi
}
probe_all() {
    if [ -n "$TO" ]; then
        $TO "$@" </dev/null 2>&1
    else
        "$@" </dev/null 2>&1
    fi
}

# ---------------------------------------------------------------- discovery

# Follow symlinks so /usr/bin/php -> /etc/alternatives/php -> php8.3 is one row.
resolve_path() {
    rp=$1
    rn=0
    while [ -L "$rp" ] && [ $rn -lt 20 ]; do
        rt=$(readlink "$rp" 2>/dev/null) || break
        [ -n "$rt" ] || break
        case "$rt" in
            /*) rp=$rt ;;
            *) rp="$(dirname "$rp")/$rt" ;;
        esac
        rn=$((rn + 1))
    done
    rd=$(cd -P "$(dirname "$rp")" 2>/dev/null && pwd -P) || rd=""
    if [ -n "$rd" ]; then
        printf '%s/%s\n' "${rd%/}" "$(basename "$rp")"
    else
        printf '%s\n' "$rp"
    fi
}

# Accept only names that are a php interpreter: php, php8.3, php83, php-fpm,
# php-fpm8.3, php8.3-fpm, php-cgi, ... (not php-config, phpize, phpunit).
valid_name() {
    vn=${1##*/}
    vn=${vn%.exe}
    case "$vn" in
        php|php-fpm|php-cgi) return 0 ;;
        php-fpm*) vr=${vn#php-fpm} ;;
        php-cgi*) vr=${vn#php-cgi} ;;
        php*) vr=${vn#php}; vr=${vr%-fpm}; vr=${vr%-cgi} ;;
        *) return 1 ;;
    esac
    case "$vr" in
        ''|*[!0-9.]*) return 1 ;;
    esac
    return 0
}

CANDS=""    # lines: run-path <TAB> display-label <TAB> resolved-path
SEEN="$NL"

add_cand() {  # path [label]
    ac=$1
    case "$ac" in
        *"$NL"*|*"$TAB"*) return 0 ;;
    esac
    [ -f "$ac" ] && [ -x "$ac" ] || return 0
    acr=$(resolve_path "$ac")
    case "$SEEN" in
        *"$NL$acr$NL"*) return 0 ;;
    esac
    SEEN="$SEEN$acr$NL"
    CANDS="$CANDS$acr$TAB${2:-$acr}$TAB$acr$NL"
}

scan_dir() {
    sd=${1%/}
    [ -n "$sd" ] && [ -d "$sd" ] || return 0
    for sf in "$sd"/php "$sd"/php[0-9]* "$sd"/php-fpm* "$sd"/php-cgi* \
              "$sd"/php.exe "$sd"/php-cgi.exe; do
        [ -e "$sf" ] || continue
        valid_name "$sf" || continue
        add_cand "$sf"
    done
}

FRANKEN=""
discover() {
    OLDIFS=$IFS
    IFS=:
    set -f
    for d in ${PATH:-}; do
        IFS=$OLDIFS
        set +f
        scan_dir "$d"
        if [ -z "$FRANKEN" ] && [ -x "${d%/}/frankenphp" ]; then
            FRANKEN="${d%/}/frankenphp"
        fi
    done
    IFS=$OLDIFS
    set +f

    for d in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin \
             /opt/*/bin /opt/*/sbin /opt/homebrew/bin /opt/homebrew/sbin \
             /opt/homebrew/opt/php*/bin /opt/homebrew/opt/php*/sbin \
             /usr/local/opt/php*/bin /usr/local/opt/php*/sbin \
             /usr/local/php*/bin /usr/local/php*/sbin \
             /opt/remi/php*/root/usr/bin /opt/remi/php*/root/usr/sbin \
             /opt/plesk/php/*/bin /opt/plesk/php/*/sbin \
             /opt/cpanel/ea-php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/sbin \
             /opt/alt/php*/usr/bin /opt/alt/php*/usr/sbin \
             /etc/php*/bin /etc/php*/*/bin; do
        scan_dir "$d"
    done
    if [ -z "$FRANKEN" ]; then
        for d in /usr/local/bin/frankenphp /usr/bin/frankenphp /opt/homebrew/bin/frankenphp; do
            [ -x "$d" ] && { FRANKEN=$d; break; }
        done
    fi
}

# Running php-fpm masters. The binary a master runs can differ from the one
# on PATH, and can be an old one that an upgrade already replaced on disk.
PROC_NOTES=""
N_MASTERS=0
N_PROC_UNSEEN=0   # running masters whose binary could not be evaluated
scan_procs() {
    command -v ps >/dev/null 2>&1 || return 0
    plist=$(ps -eo pid=,args= 2>/dev/null | grep 'php-fpm: master process' | grep -v 'grep ')
    [ -n "$plist" ] || return 0
    OLDIFS=$IFS
    IFS=$NL
    set -f
    for pl in $plist; do
        IFS=$OLDIFS
        set +f
        ppid_=$(printf '%s\n' "$pl" | awk '{print $1}')
        is_uint "$ppid_" || continue
        N_MASTERS=$((N_MASTERS + 1))
        pconf=$(printf '%s\n' "$pl" | sed -n 's/.*master process (\(.*\)).*/\1/p')
        pexe=$(readlink "/proc/$ppid_/exe" 2>/dev/null) || pexe=""
        case "$pexe" in
            *" (deleted)")
                PROC_NOTES="${PROC_NOTES}running php-fpm master pid $ppid_ (${pconf:-config unknown}) runs a binary that was replaced on disk -- restart it to pick up the upgrade$NL"
                if [ -x "/proc/$ppid_/exe" ]; then
                    CANDS="$CANDS/proc/$ppid_/exe${TAB}php-fpm pid $ppid_ (stale)$TAB$NL"
                else
                    N_PROC_UNSEEN=$((N_PROC_UNSEEN + 1))
                fi ;;
            '')
                N_PROC_UNSEEN=$((N_PROC_UNSEEN + 1))
                PROC_NOTES="${PROC_NOTES}running php-fpm master pid $ppid_ (${pconf:-config unknown}): binary path not readable (not root, or no /proc) -- its version was NOT checked$NL" ;;
            *)
                PROC_NOTES="${PROC_NOTES}running php-fpm master pid $ppid_ (${pconf:-config unknown}): $pexe$NL"
                if [ -f "$pexe" ] && [ -x "$pexe" ]; then
                    add_cand "$pexe"
                elif [ -x "/proc/$ppid_/exe" ]; then
                    # binary lives in another mount namespace (container)
                    CANDS="$CANDS/proc/$ppid_/exe${TAB}php-fpm pid $ppid_$TAB$NL"
                else
                    N_PROC_UNSEEN=$((N_PROC_UNSEEN + 1))
                fi ;;
        esac
    done
    IFS=$OLDIFS
    set +f
}

# ------------------------------------------------------------ version gates

# "8.5.12", "8.5.13RC1", "8.6.0-dev", "8.3.6-0ubuntu0.24.04.5" -> V_MAJ V_MIN
# V_PAT V_SUF. Returns 1 when the string is not MAJOR.MINOR.PATCH[suffix].
parse_version() {
    V_MAJ=""; V_MIN=""; V_PAT=""; V_SUF=""
    case "$1" in
        [0-9]*.[0-9]*.[0-9]*) : ;;
        *) return 1 ;;
    esac
    pv_maj=${1%%.*}
    pv_rest=${1#*.}
    pv_min=${pv_rest%%.*}
    pv_rest=${pv_rest#*.}
    pv_pat=${pv_rest%%[!0-9]*}
    is_uint "$pv_maj" && is_uint "$pv_min" && is_uint "$pv_pat" || return 1
    V_MAJ=$((10#$pv_maj))
    V_MIN=$((10#$pv_min))
    V_PAT=$((10#$pv_pat))
    V_SUF=${pv_rest#"$pv_pat"}
    return 0
}

# Gate shared by the 8.2-8.5 CVEs. Sets G_STATE (below | ok | unknown), G_WHY
# (short column text), G_NOTE, G_FIXED, G_PRE, and for a series with no
# fixed-in entry G_OLDER / G_NEWER (older / newer than every listed series).
gate_std() {
    G_STATE=unknown; G_WHY=""; G_NOTE=""; G_FIXED=""; G_OLDER=0; G_NEWER=0; G_PRE=0
    case "$(lower "$V_SUF")" in
        rc*|-rc*|alpha*|-alpha*|beta*|-beta*|dev*|-dev*) G_PRE=1 ;;
    esac
    for g_f in $FIXED_IN; do
        case "$g_f" in
            "$V_MAJ.$V_MIN".*) G_FIXED=$g_f; break ;;
        esac
    done
    if [ -z "$G_FIXED" ]; then
        G_OLDER=1; G_NEWER=1
        for g_f in $FIXED_IN; do
            g_fm=${g_f%%.*}; g_fr=${g_f#*.}; g_fn=${g_fr%%.*}
            if [ "$V_MAJ" -lt "$g_fm" ] || { [ "$V_MAJ" -eq "$g_fm" ] && [ "$V_MIN" -lt "$g_fn" ]; }; then
                G_NEWER=0
            else
                G_OLDER=0
            fi
        done
        if [ "$G_NEWER" -eq 1 ]; then
            G_WHY="series?"
            G_NOTE="series $V_MAJ.$V_MIN is newer than every series in the fixed-in list; not evaluated"
        elif [ "$G_OLDER" -eq 1 ]; then
            G_WHY="EOL"
            G_NOTE="series $V_MAJ.$V_MIN is end-of-life: no fixed release exists -- treat as exposed and move to a supported series"
        else
            G_WHY="series?"
            G_NOTE="series $V_MAJ.$V_MIN has no entry in the fixed-in list; not evaluated"
        fi
        return 0
    fi
    g_fp=${G_FIXED##*.}
    if [ "$V_PAT" -lt "$g_fp" ]; then
        G_STATE=below
        G_WHY="< $G_FIXED"
    elif [ "$G_PRE" -eq 1 ]; then
        G_WHY="pre-rel?"
        G_NOTE="pre-release build ($V_MAJ.$V_MIN.$V_PAT$V_SUF) at/above $G_FIXED: RC and -dev builds can predate the security fix; not evaluated"
    else
        G_STATE=ok
        G_WHY=">= $G_FIXED"
    fi
    return 0
}

# Gate of the 8.5-only CVEs (129474, 129182). Sets G85 to
# na (series not affected) | vuln (unpatched 8.5) | ok | unknown.
gate_85() {
    if [ "$V_MAJ" -lt 8 ] || { [ "$V_MAJ" -eq 8 ] && [ "$V_MIN" -lt 5 ]; }; then
        G85=na
    elif [ "$V_MAJ" -gt 8 ] || [ "$V_MIN" -gt 5 ]; then
        if [ "$G_PRE" -eq 1 ]; then G85=unknown; else G85=na; fi
    elif [ "$V_PAT" -lt "$FIXED_85_PAT" ]; then
        G85=vuln
    elif [ "$G_PRE" -eq 1 ]; then
        G85=unknown
    else
        G85=ok
    fi
}

# ----------------------------------------------------- php -i configuration

INFO=""
ini_get() {  # local value of a directive / info key; "no value" -> empty
    printf '%s\n' "$INFO" | awk -F' => ' -v k="$1" '
        $1 == k { v = $2; sub(/[ \t\r]+$/, "", v); if (v == "no value" || v == "(none)") v = ""; print v; exit }'
}
ini_has() { printf '%s\n' "$INFO" | awk -F' => ' -v k="$1" '$1 == k { f = 1; exit } END { exit f ? 0 : 1 }'; }

is_on() {
    case "$(lower "$1")" in
        1|on|yes|true|enabled) return 0 ;;
    esac
    return 1
}

# Does this error_log value name a file? Empty = SAPI default logger (stderr,
# or FPM's own log), "syslog" = syslog; everything else is opened as a file.
is_file_log() {
    case "$(lower "$1")" in
        ''|syslog) return 1 ;;
    esac
    return 0
}

# Last uncommented "key = value" of a php.ini-style file. Quotes, trailing
# comments and whitespace are stripped. Prints nothing when the key is absent.
ini_file_last() {  # key file
    [ -f "$2" ] && [ -r "$2" ] || return 0
    awk -v k="$1" '
        /^[ \t]*[;#]/ { next }
        {
            line = $0
            sub(/\r$/, "", line)
            eq = index(line, "=")
            if (eq == 0) next
            name = substr(line, 1, eq - 1)
            gsub(/[ \t]/, "", name)
            if (name != k) next
            v = substr(line, eq + 1)
            sub(/^[ \t]+/, "", v)
            if (v ~ /^"/) { v = substr(v, 2); sub(/".*$/, "", v) }
            else if (v ~ /^\047/) { v = substr(v, 2); sub(/\047.*$/, "", v) }
            else { sub(/[ \t]*;.*$/, "", v) }
            sub(/[ \t]+$/, "", v)
            last = v; found = 1
        }
        END { if (found) print last }' "$2" 2>/dev/null
}

# Is a timezone name absent from the system zone database? Only a hint: PHP
# ships its own database and matches names case-insensitively.
tz_suspect() {
    [ -n "$1" ] || return 1
    case "$1" in
        *'$'*) return 1 ;;
        *[!A-Za-z0-9_+/-]*) return 0 ;;
    esac
    case "$(lower "$1")" in
        utc|gmt|z) return 1 ;;
    esac
    [ -d /usr/share/zoneinfo ] || return 1
    [ -e "/usr/share/zoneinfo/$1" ] && return 1
    return 0
}

# Distribution package owning a binary, if any. Sets PKG.
pkg_owner() {
    PKG=""
    [ -n "$1" ] || return 0
    if command -v dpkg-query >/dev/null 2>&1; then
        po=$(dpkg-query -S "$1" 2>/dev/null | sed -n '1s/: .*//p')
        po=${po%%:*}
        if [ -n "$po" ]; then
            pov=$(dpkg-query -W -f='${Version}' "$po" 2>/dev/null | sed -n 1p)
            PKG="$po $pov"
            return 0
        fi
    fi
    if command -v rpm >/dev/null 2>&1; then
        po=$(rpm -qf "$1" 2>/dev/null | sed -n 1p) || po=""
        case "$po" in
            ''|*"not owned"*|*" "*) : ;;
            *) PKG=$po ;;
        esac
    fi
    return 0
}

# ------------------------------- web-side signals: gathered once, host-wide

SESS_WATCH='session\.(upload_progress\.enabled|serialize_handler|save_handler|save_path)'
GATE_DIRS='zend\.exception_ignore_args|fatal_error_backtraces'
# One pattern for every per-directory / per-request INI line the gates read.
RE_UNION="php_(admin_)?(value|flag)|PHP_(ADMIN_)?VALUE|$SESS_WATCH|$GATE_DIRS"
# 129474: a line that turns zend.exception_ignore_args off, in any syntax
# (pool php_admin_flag[...] = off, Apache php_flag ... off, PHP_VALUE "...=0",
# .user.ini "... = 0", ini_set('...', '0')).
OPENS="zend\\.exception_ignore_args[]'\"]*[[:space:]]*[=,]?[[:space:]]*['\"]?(0|off|no|false)([^0-9a-z_]|\$)"
# 129182: delivery surface and the settings named in the advisory.
PHPDIR_L='^[^:]+:[0-9]+:[[:space:]]*php_(admin_)?(value|flag)[[:space:]]'
ENVVAL='(^|[^A-Za-z0-9_])PHP_(ADMIN_)?VALUE([^A-Za-z0-9_]|$)'
CONFLICT='max_memory_limit|memory_limit|zlib\.output_compression|output_handler'
# Application code patterns (PHP2026_APP_PATH).
RE_APP_INISET="ini_set[[:space:]]*\\([[:space:]]*['\"](session\\.serialize_handler|session\\.save_handler|zend\\.exception_ignore_args|fatal_error_backtraces)['\"]"
RE_APP_SEROPT="['\"]serialize_handler['\"][[:space:]]*=>"
RE_H1='session_set_save_handler[[:space:]]*\(|SessionHandlerInterface|SessionUpdateTimestampHandlerInterface|extends[[:space:]]+\\?SessionHandler([^A-Za-z0-9_]|$)'
RE_H2='stream_wrapper_register[[:space:]]*\(|function[[:space:]]+stream_close[[:space:]]*\('
RE_H3='\$_SESSION[[:space:]]*(\[[^]]*\][[:space:]]*)+=[[:space:]]*@?\\?(fopen|tmpfile|fsockopen|pfsockopen|stream_socket_client|stream_socket_server|popen|proc_open|opendir|curl_init|socket_create|finfo_open|xml_parser_create|gzopen|bzopen|dba_open|ftp_connect|ftp_ssl_connect)[[:space:]]*\('

POOL_LINES=""    # php_value & co. lines of php-fpm pool files, file:line:text
WEB_LINES=""     # RE_UNION lines of web-server config
PERDIR_LINES=""  # RE_UNION lines of .htaccess / .user.ini
UINI_FILES=""    # .user.ini files
APP_LINES=""     # application code hits
APP_BAD=0
OVR_UP=0         # an override touches session.upload_progress.enabled
OVR_SH=0         # an override touches session.save_handler
SESS_HITS=""     # every session override line found
SEEN_SER=""      # serialize handlers seen (mixed-handler note)
WEB_FILE_LOG=""  # web-side "source: error_log = file" lines
WEB_TZ=""        # web-side suspicious date.timezone lines
EIA_OPEN=""      # 129474: lines that open the gate
EIA_REST=""      # 129474: other lines on the gate directives
S_APACHE=""; S_HTA=""; S_ENV=""; S_POOL=""; S_CONFLICT=""
N_SURF=0
SURF_TXT="none"
APP_H1=""; APP_H2=""; APP_H3=""; APP_SER=""

# grep -r over files/directories, comment lines dropped. file:line:text
cfg_grep() {  # pattern path...
    cg_p=$1
    shift
    for cg in "$@"; do
        [ -e "$cg" ] && [ -r "$cg" ] || continue
        grep -rIEHni -- "$cg_p" "$cg" 2>/dev/null
    done | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*([#;]|//)'
}

perdir_find() {  # root maxdepth-or-empty find-tail...
    pf_r=$1; pf_d=$2
    shift 2
    if [ -n "$pf_d" ]; then
        find "$pf_r" -maxdepth "$pf_d" \( -name node_modules -o -name .git \) -prune -o "$@" 2>/dev/null
    else
        find "$pf_r" \( -name node_modules -o -name .git \) -prune -o "$@" 2>/dev/null
    fi
}

files_of() { printf '%s\n' "$1" | sed -e '/^$/d' -e 's/:[0-9][0-9]*:.*$//' | sort -u; }

add_ser() {
    [ -n "$1" ] || return 0
    case " $SEEN_SER " in
        *" $1 "*) : ;;
        *) SEEN_SER="${SEEN_SER:+$SEEN_SER }$1" ;;
    esac
}

web_note_log() {  # source value
    if is_file_log "$2"; then
        WEB_FILE_LOG="$WEB_FILE_LOG$1: error_log = $2$NL"
    fi
}
web_note_tz() {  # source value
    if tz_suspect "$2"; then
        WEB_TZ="$WEB_TZ$1: date.timezone = $2$NL"
    fi
}

gather_web() {
    POOL_LINES=$(cfg_grep '^[[:space:]]*php_(admin_)?(value|flag)\[' \
        /etc/php/*/fpm/pool.d /etc/php/*/fpm/php-fpm.conf \
        /etc/php-fpm.d /etc/php-fpm.conf /etc/php*/php-fpm.d \
        /etc/php/php-fpm.d /etc/opt/remi/php*/php-fpm.d \
        /usr/local/etc/php-fpm.d /usr/local/etc/php-fpm.conf \
        /usr/local/etc/php/*/php-fpm.d /opt/homebrew/etc/php/*/php-fpm.d \
        /opt/plesk/php/*/etc/php-fpm.d /opt/cpanel/ea-php*/root/etc/php-fpm.d | sort -u)

    WEB_LINES=$(
        cfg_grep "$RE_UNION" \
            /etc/nginx /usr/local/etc/nginx /opt/homebrew/etc/nginx \
            /etc/apache2 /etc/httpd /usr/local/etc/apache2 /usr/local/etc/httpd \
            /opt/homebrew/etc/httpd /usr/local/apache2/conf \
            /etc/caddy /etc/lighttpd /etc/haproxy /usr/local/lsws/conf
        OLDIFS=$IFS
        IFS=:
        set -f
        for gw_d in $WEB_CONF_EXTRA; do
            IFS=$OLDIFS
            set +f
            [ -n "$gw_d" ] && cfg_grep "$RE_UNION" "$gw_d"
        done
        IFS=$OLDIFS
        set +f
    )
    WEB_LINES=$(printf '%s\n' "$WEB_LINES" | sed '/^$/d' | sort -u)

    if [ -n "$APP_PATH" ]; then
        if [ ! -d "$APP_PATH" ] || [ ! -r "$APP_PATH" ]; then APP_BAD=1; fi
    fi
    PERDIR_LINES=$(
        for gw_d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /home/*/public_html; do
            [ -d "$gw_d" ] && [ -r "$gw_d" ] || continue
            perdir_find "$gw_d" 6 -type f \( -name '.htaccess' -o -name '.user.ini' \) \
                -exec grep -EHni -- "$RE_UNION" {} +
        done
        if [ -n "$APP_PATH" ] && [ "$APP_BAD" -eq 0 ]; then
            perdir_find "$APP_PATH" "" -type f \( -name '.htaccess' -o -name '.user.ini' \) \
                -exec grep -EHni -- "$RE_UNION" {} +
        fi
    )
    PERDIR_LINES=$(printf '%s\n' "$PERDIR_LINES" | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*[#;]' | sed '/^$/d' | sort -u)
    UINI_FILES=$(
        for gw_d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /home/*/public_html; do
            [ -d "$gw_d" ] && [ -r "$gw_d" ] || continue
            perdir_find "$gw_d" 6 -type f -name '.user.ini' -print
        done
        if [ -n "$APP_PATH" ] && [ "$APP_BAD" -eq 0 ]; then
            perdir_find "$APP_PATH" "" -type f -name '.user.ini' -print
        fi
    )
    UINI_FILES=$(printf '%s\n' "$UINI_FILES" | sed '/^$/d' | sort -u)

    if [ -n "$APP_PATH" ] && [ "$APP_BAD" -eq 0 ]; then
        APP_LINES=$(perdir_find "$APP_PATH" "" -type f \
            \( -name '*.php' -o -name '*.inc' -o -name '*.phtml' -o -name '*.module' \) \
            -exec grep -EHn -- "$RE_APP_INISET|$RE_APP_SEROPT|$RE_H1|$RE_H2|$RE_H3" {} +)
    fi

    # --- 115560 / 126714: overrides of the session settings
    gw_pool=$(printf '%s\n' "$POOL_LINES" | grep -E "php_(admin_)?(value|flag)\\[$SESS_WATCH\\]")
    gw_web=$(printf '%s\n' "$WEB_LINES" | grep -Ei "$SESS_WATCH")
    gw_dir=$(printf '%s\n' "$PERDIR_LINES" | grep -Ei "$SESS_WATCH")
    SESS_HITS=$(printf '%s\n%s\n%s\n' "$gw_pool" "$gw_web" "$gw_dir" | sed '/^$/d')
    if printf '%s\n' "$SESS_HITS" | grep -Eiq 'session\.upload_progress\.enabled'; then OVR_UP=1; fi
    if printf '%s\n' "$SESS_HITS" | grep -Eiq 'session\.save_handler'; then OVR_SH=1; fi
    if printf '%s\n' "$APP_LINES" | grep -Eq "ini_set[[:space:]]*\\([[:space:]]*['\"]session\\.save_handler['\"]"; then OVR_SH=1; fi
    APP_SER=$(files_of "$(printf '%s\n' "$APP_LINES" | grep -E "ini_set[[:space:]]*\\([[:space:]]*['\"]session\\.serialize_handler['\"]|$RE_APP_SEROPT")")
    for gw_h in $(printf '%s\n' "$gw_pool" | sed -n 's/.*session\.serialize_handler\][[:space:]]*=[[:space:]]*"\{0,1\}\([A-Za-z_][A-Za-z_0-9]*\).*/\1/p' | tr '[:upper:]' '[:lower:]'); do
        add_ser "$gw_h"
    done

    # --- 129496: web-side error_log / date.timezone
    for wi in /etc/php/*/fpm/php.ini /etc/php/*/fpm/conf.d/*.ini \
              /etc/php/*/apache2/php.ini /etc/php/*/apache2/conf.d/*.ini \
              /etc/php/*/cgi/php.ini /etc/php/*/cgi/conf.d/*.ini \
              /etc/php.ini /etc/php.d/*.ini \
              /etc/php[0-9]*/php.ini /etc/php[0-9]*/conf.d/*.ini \
              /etc/php[0-9]*/fpm/php.ini /etc/php[0-9]*/apache2/php.ini \
              /usr/local/etc/php/php.ini /usr/local/etc/php/conf.d/*.ini \
              /usr/local/etc/php/*/php.ini /usr/local/etc/php.ini \
              /usr/local/lib/php.ini \
              /opt/homebrew/etc/php/*/php.ini /opt/homebrew/etc/php/*/conf.d/*.ini \
              /etc/opt/remi/php*/php.ini /etc/opt/remi/php*/php.d/*.ini \
              /opt/plesk/php/*/etc/php.ini /opt/plesk/php/*/etc/php.d/*.ini \
              /opt/cpanel/ea-php*/root/etc/php.ini /opt/cpanel/ea-php*/root/etc/php.d/*.ini \
              /opt/alt/php*/etc/php.ini; do
        [ -f "$wi" ] && [ -r "$wi" ] || continue
        wv=$(ini_file_last error_log "$wi")
        [ -n "$wv" ] && web_note_log "$wi" "$wv"
        wv=$(ini_file_last date.timezone "$wi")
        [ -n "$wv" ] && web_note_tz "$wi" "$wv"
    done
    # Pools: only php_value / php_admin_value count. A bare "error_log =" in
    # php-fpm.conf is FPM's own log and is never collected.
    gw_l=$(printf '%s\n' "$POOL_LINES" | tr -d '\r' | sed -n \
        -e 's/^\([^:]*\):[0-9]*:[[:space:]]*php_\(admin_\)\{0,1\}value\[error_log\][[:space:]]*=[[:space:]]*\(.*\)$/error_log|\1|\3/p' \
        -e 's/^\([^:]*\):[0-9]*:[[:space:]]*php_\(admin_\)\{0,1\}value\[date\.timezone\][[:space:]]*=[[:space:]]*\(.*\)$/date.timezone|\1|\3/p')
    gw_a=$(printf '%s\n' "$WEB_LINES" | tr -d '\r' | grep -Ei '^[^:]+:[0-9]+:[[:space:]]*php_(admin_)?value[[:space:]]+error_log[[:space:]]' \
        | sed 's/^\([^:]*\):[0-9]*:[[:space:]]*[^[:space:]]*[[:space:]]*[^[:space:]]*[[:space:]]*\(.*\)$/error_log|\1|\2/')
    OLDIFS=$IFS
    IFS=$NL
    set -f
    for gw_e in $gw_l $gw_a; do
        IFS=$OLDIFS
        set +f
        gw_k=${gw_e%%|*}; gw_r=${gw_e#*|}; gw_f=${gw_r%%|*}; gw_v=${gw_r#*|}
        gw_v=$(printf '%s' "$gw_v" | sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/")
        [ -n "$gw_v" ] || continue
        case "$gw_k" in
            error_log) web_note_log "$gw_f (pool / vhost)" "$gw_v" ;;
            *) web_note_tz "$gw_f (pool)" "$gw_v" ;;
        esac
    done
    IFS=$OLDIFS
    set +f
    WEB_FILE_LOG=${WEB_FILE_LOG%"$NL"}
    WEB_TZ=${WEB_TZ%"$NL"}

    # --- 129474: lines on the gate directives
    gw_g=$(printf '%s\n%s\n%s\n%s\n' "$POOL_LINES" "$WEB_LINES" "$PERDIR_LINES" \
        "$(printf '%s\n' "$APP_LINES" | grep -Ei "ini_set[[:space:]]*\\([[:space:]]*['\"]($GATE_DIRS)['\"]")" \
        | sed '/^$/d' | grep -Ei -- "$GATE_DIRS" | sort -u)
    EIA_OPEN=$(printf '%s\n' "$gw_g" | sed '/^$/d' | grep -Ei -- "$OPENS")
    EIA_REST=$(printf '%s\n' "$gw_g" | sed '/^$/d' | grep -Eiv -- "$OPENS")

    # --- 129182: per-directory / per-request INI override surface
    S_APACHE=$(printf '%s\n' "$WEB_LINES" | grep -Ei -- "$PHPDIR_L")
    S_ENV=$(printf '%s\n' "$WEB_LINES" | grep -E -- "$ENVVAL")
    S_HTA=$(printf '%s\n' "$PERDIR_LINES" | grep -E '/\.htaccess:[0-9]+:' | grep -Ei -- "$PHPDIR_L|PHP_(ADMIN_)?VALUE")
    S_POOL=$(printf '%s\n' "$POOL_LINES" | grep -Ei -- "\\[($CONFLICT)\\]")
    gw_a=$(count_lines "$S_APACHE"); gw_h=$(count_lines "$S_HTA"); gw_e=$(count_lines "$S_ENV")
    N_SURF=$((gw_a + gw_h + gw_e))
    if [ "$N_SURF" -gt 0 ]; then
        S_CONFLICT=$(printf '%s\n%s\n%s\n' "$S_APACHE" "$S_HTA" "$S_ENV" | sed '/^$/d' | grep -Ei -- "$CONFLICT")
        SURF_TXT=""
        [ "$gw_a" -gt 0 ] && SURF_TXT="$SURF_TXT apache-conf($gw_a)"
        [ "$gw_h" -gt 0 ] && SURF_TXT="$SURF_TXT htaccess($gw_h)"
        [ "$gw_e" -gt 0 ] && SURF_TXT="$SURF_TXT PHP_VALUE($gw_e)"
        [ -n "$S_CONFLICT" ] && SURF_TXT="$SURF_TXT conflict-candidates($(count_lines "$S_CONFLICT"))"
        SURF_TXT=${SURF_TXT# }
    fi

    # --- 129481: application code hints
    APP_H1=$(files_of "$(printf '%s\n' "$APP_LINES" | grep -E -- "$RE_H1")")
    APP_H2=$(files_of "$(printf '%s\n' "$APP_LINES" | grep -E -- "$RE_H2")")
    APP_H3=$(files_of "$(printf '%s\n' "$APP_LINES" | grep -E -- "$RE_H3")")
    return 0
}

# ------------------------------ 129289: front end, FastCGI connection reuse

# Lines that turn FastCGI connection reuse on (grep -E, case-insensitive,
# applied to "file:line:text" with comment lines already removed).
RE_REUSE='fastcgi_keep_conn[[:space:]]+on[[:space:]]*;|enablereuse[[:space:]]*=[[:space:]]*on([^a-z]|$)|use-fcgi-app|proto[[:space:]]+fcgi|^[^:]*:[0-9]+:[[:space:]]*fcgi-app[[:space:]]|option[[:space:]]+(keep-conn|mpxs-conns)'
# Lines that show the front end talks FastCGI at all.
RE_USE='fastcgi_pass|proxy:fcgi:|fcgi://|proxy_fcgi|php_fastcgi'
RE_ANY="fastcgi_keep_conn|enablereuse|use-fcgi-app|proto[[:space:]]+fcgi|fcgi-app|keep-conn|mpxs-conns|$RE_USE"

FE_DIRS=0        # front-end config locations inspected
FE_DENIED=0      # files that could not be read
FE_OTHER=""      # front ends present but not evaluable (LiteSpeed, Caddy)
FE_HITS=""       # reuse lines, file:line:text
FE_SURF=""       # one line per location
FE_STATE=unknown # reuse | clean | unknown
FE_WHY=""

scan_conf() {  # path
    sc=${1%/}
    [ -n "$sc" ] || return 0
    [ -d "$sc" ] || [ -f "$sc" ] || return 0
    FE_DIRS=$((FE_DIRS + 1))
    if [ ! -r "$sc" ]; then
        FE_DENIED=$((FE_DENIED + 1))
        FE_SURF="${FE_SURF}$sc  not readable (run as root)$NL"
        return 0
    fi
    sc_raw=$(find "$sc" -type f -exec grep -HnIiE "$RE_ANY" {} + 2>&1)
    sc_den=$(printf '%s\n' "$sc_raw" | grep -ci 'permission denied')
    sc_m=$(printf '%s\n' "$sc_raw" | grep -vi 'permission denied' | grep -E '^[^:]*:[0-9]+:' | grep -vE '^[^:]*:[0-9]+:[[:space:]]*(#|//)')
    sc_m=$(printf '%s\n' "$sc_m" | grep -viE '^[^:]*:[0-9]+:[[:space:]]*no[[:space:]]+option')
    sc_reuse=$(printf '%s\n' "$sc_m" | grep -iE "$RE_REUSE")
    sc_use=$(printf '%s\n' "$sc_m" | grep -iE "$RE_USE")
    sc_nr=$(count_lines "$sc_reuse")
    sc_nu=$(count_lines "$sc_use")
    is_uint "$sc_den" || sc_den=0
    FE_DENIED=$((FE_DENIED + sc_den))
    [ -n "$sc_reuse" ] && FE_HITS="$FE_HITS$sc_reuse$NL"
    sc_txt="FastCGI connection reuse: "
    if [ "$sc_nr" -gt 0 ]; then
        sc_txt="${sc_txt}FOUND, $sc_nr directive(s)"
    else
        sc_txt="${sc_txt}none found"
    fi
    sc_txt="$sc_txt; FastCGI backend references: $sc_nu"
    [ "$sc_den" -gt 0 ] && sc_txt="$sc_txt; $sc_den unreadable file(s)"
    case "$sc" in
        *caddy*|*Caddy*)
            if [ "$sc_nu" -gt 0 ]; then
                FE_OTHER="${FE_OTHER}Caddy php_fastcgi ($sc); "
                sc_txt="$sc_txt; Caddy connection handling not evaluated"
            fi ;;
    esac
    FE_SURF="${FE_SURF}$sc  $sc_txt$NL"
}

# Where the php-fpm pools listen: unix socket / loopback only, or reachable
# by a front end on another host. Sets POOL_STATE (local | remote | unknown).
POOL_STATE=unknown
POOL_REMOTE=""
scan_pool_listen() {
    sp_seen=0
    for sp in /etc/php/*/fpm/pool.d/*.conf /etc/php/*/fpm/php-fpm.conf \
              /etc/php-fpm.d/*.conf /etc/php-fpm.conf /etc/php*/php-fpm.d/*.conf \
              /etc/php/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf \
              /usr/local/etc/php-fpm.d/*.conf /usr/local/etc/php-fpm.conf \
              /usr/local/etc/php/*/php-fpm.d/*.conf \
              /opt/homebrew/etc/php/*/php-fpm.d/*.conf \
              /opt/plesk/php/*/etc/php-fpm.d/*.conf \
              /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf; do
        [ -f "$sp" ] || continue
        if [ ! -r "$sp" ]; then
            POOL_REMOTE="$POOL_REMOTE$sp: not readable$NL"
            continue
        fi
        sp_l=$(sed -n 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*//p' "$sp" 2>/dev/null | tr -d '"'"'"'\r' | sed 's/[[:space:]]*\(;.*\)\{0,1\}$//')
        [ -n "$sp_l" ] || continue
        OLDIFS=$IFS
        IFS=$NL
        set -f
        for sp_v in $sp_l; do
            IFS=$OLDIFS
            set +f
            sp_seen=$((sp_seen + 1))
            case "$sp_v" in
                /*|127.*:*|localhost:*|'[::1]:'*) : ;;
                *) POOL_REMOTE="$POOL_REMOTE$sp: listen = $sp_v$NL" ;;
            esac
        done
        IFS=$OLDIFS
        set +f
    done
    if [ -n "$POOL_REMOTE" ]; then
        POOL_STATE=remote
    elif [ "$sp_seen" -gt 0 ]; then
        POOL_STATE=local
    fi
}

scan_frontend() {
    for sf_d in /etc/nginx /usr/local/etc/nginx /opt/homebrew/etc/nginx /usr/local/nginx/conf \
                /etc/openresty /usr/local/openresty/nginx/conf \
                /etc/apache2 /etc/httpd /usr/local/etc/apache2 /usr/local/etc/apache24 \
                /usr/local/etc/httpd /usr/local/apache2/conf /opt/homebrew/etc/httpd \
                /etc/haproxy /usr/local/etc/haproxy /opt/homebrew/etc/haproxy \
                /etc/caddy; do
        scan_conf "$sf_d"
    done
    OLDIFS=$IFS
    IFS=:
    set -f
    for sf_d in $WEB_CONF_EXTRA; do
        IFS=$OLDIFS
        set +f
        [ -n "$sf_d" ] || continue
        if [ -e "$sf_d" ]; then
            scan_conf "$sf_d"
        else
            FE_DENIED=$((FE_DENIED + 1))
            FE_SURF="${FE_SURF}$sf_d  does not exist (PHP2026_WEB_CONF_DIRS)$NL"
        fi
    done
    IFS=$OLDIFS
    set +f

    # LiteSpeed / OpenLiteSpeed keep persistent LSAPI connections by design;
    # their configuration is not evaluated here.
    for sf_d in /usr/local/lsws /opt/lsws /etc/litespeed; do
        [ -d "$sf_d" ] && FE_OTHER="${FE_OTHER}LiteSpeed/LSAPI ($sf_d); "
    done
    if command -v ps >/dev/null 2>&1; then
        if ps -eo args= 2>/dev/null | grep -E '(^|/)(litespeed|openlitespeed|lshttpd)( |$)' | grep -v 'grep ' >/dev/null 2>&1; then
            case "$FE_OTHER" in
                *LiteSpeed*) : ;;
                *) FE_OTHER="${FE_OTHER}LiteSpeed/LSAPI (running process); " ;;
            esac
        fi
    fi

    scan_pool_listen

    FE_HITS=${FE_HITS%"$NL"}
    if [ -n "$FE_HITS" ]; then
        FE_STATE=reuse
        FE_WHY="FastCGI connection reuse is configured ($(count_lines "$FE_HITS") directive(s))"
    elif [ "$FE_DIRS" -eq 0 ]; then
        FE_WHY="no nginx / Apache / HAProxy config found on this host -- front end not inspected (set PHP2026_WEB_CONF_DIRS)"
    elif [ "$FE_DENIED" -gt 0 ]; then
        FE_WHY="front-end config only partly readable -- run as root"
    elif [ -n "$FE_OTHER" ]; then
        FE_WHY="a front end that cannot be evaluated is present (${FE_OTHER%; })"
    elif [ "$POOL_STATE" != local ]; then
        FE_WHY="no reuse directive in local config, but a remote front end cannot be ruled out (pool listen address)"
    else
        FE_STATE=clean
        FE_WHY="front end inspected: no FastCGI connection reuse; pools are local-only"
    fi
}

# ------------------------------------------------- per-install gate checks
#
# Each ev_* reads the globals set by check_php (c_label, c_sapi, c_zts,
# c_info_ok, INFO, G_*, G85) and records one result with contrib.

N_FPM_ROWS=0; N_NONFPM_VULN=0; N_VULN_FPM=0
N_CLI_ROWS=0; N_FPM_EVAL=0; N_VULN85=0; N_BELOW=0; N_CFG_ONLY=0

# CVE-2026-129289: php-fpm below the fix AND FastCGI connection reuse.
ev_fpm() {
    e_v=$G_STATE; e_w=$G_WHY
    # The bug exists since 5.6.0: end-of-life series are vulnerable, no fix.
    if [ -z "$G_FIXED" ] && [ "$G_OLDER" -eq 1 ] && { [ "$V_MAJ" -gt 5 ] || { [ "$V_MAJ" -eq 5 ] && [ "$V_MIN" -ge 6 ]; }; }; then
        e_v=below; e_w="end-of-life, no fix"
    fi
    if [ "$c_sapi" = fpm-fcgi ]; then
        N_FPM_ROWS=$((N_FPM_ROWS + 1))
        case "$e_v" in
            ok) contrib 1 NOT_IMPACTED "$c_label: php-fpm patched ($e_w)" ;;
            below)
                N_VULN_FPM=$((N_VULN_FPM + 1))
                case "$FE_STATE" in
                    reuse) e_s=IMPACTED ;;
                    clean) e_s=NOT_IMPACTED ;;
                    *)     e_s=UNKNOWN ;;
                esac
                contrib 1 "$e_s" "$c_label: php-fpm $e_w; $FE_WHY" ;;
            *) contrib 1 UNKNOWN "$c_label: php-fpm version not evaluated (${e_w:-?})" ;;
        esac
    else
        case "$e_v" in
            ok) contrib 1 NOT_IMPACTED "$c_label: patched (not the FPM SAPI)" ;;
            below)
                N_NONFPM_VULN=$((N_NONFPM_VULN + 1))
                cnote 1 "$c_label: $e_w, but not the FPM SAPI -- does not decide this CVE" ;;
            *) cnote 1 "$c_label: not the FPM SAPI; version not evaluated (${e_w:-?})" ;;
        esac
    fi
}

# Shared tail of the two session CVEs: PRE is met | possible | ruled_out.
ev_session_tail() {  # cve-index surface override-flag setting-name
    case "$G_STATE" in
        ok) contrib "$1" NOT_IMPACTED "$c_label: patched ($G_WHY)" ;;
        below)
            case "$PRE" in
                ruled_out)
                    if [ "$c_sapi" = fpm-fcgi ] && [ "$3" -eq 0 ]; then
                        N_CFG_ONLY=$((N_CFG_ONLY + 1))
                        contrib "$1" NOT_IMPACTED "$c_label: $G_WHY, but this php-fpm configuration rules the precondition out and no override was found ($2). STILL UNPATCHED"
                    elif [ "$c_sapi" = fpm-fcgi ]; then
                        contrib "$1" UNKNOWN "$c_label: $G_WHY; base ini rules the precondition out ($2), but a pool / web-server / app override touches $4 -- review"
                    else
                        contrib "$1" UNKNOWN "$c_label: $G_WHY; precondition ruled out only in this ${c_sapi:-unidentified} ini ($2), which is not the web SAPI configuration -- cannot decide"
                    fi ;;
                met) contrib "$1" IMPACTED "$c_label: $G_WHY; precondition MET: $2" ;;
                *) contrib "$1" IMPACTED "$c_label: $G_WHY; precondition NOT RULED OUT: $2" ;;
            esac ;;
        *) contrib "$1" UNKNOWN "$c_label: version gate undecided (${G_NOTE:-$G_WHY})" ;;
    esac
}

# CVE-2026-115560: upload progress on (+ non-default serialize handler).
ev_serializer() {
    PRE=possible
    e_surf="no usable '-i' output; audit this SAPI's ini by hand"
    if [ "$c_info_ok" -eq 1 ]; then
        if ! ini_has session.serialize_handler; then
            PRE=ruled_out
            e_surf="no session extension in this configuration"
        else
            e_up=$(ini_get session.upload_progress.enabled)
            e_ser=$(lower "$(ini_get session.serialize_handler)")
            add_ser "$e_ser"
            if ! ini_has session.upload_progress.enabled || [ -z "$e_up" ]; then
                e_surf="session.upload_progress.enabled not readable; serialize_handler=${e_ser:-?}"
            elif is_on "$e_up"; then
                case "$e_ser" in
                    php_serialize|php_binary)
                        PRE=met
                        e_surf="upload_progress.enabled=On + serialize_handler=$e_ser" ;;
                    *)
                        e_surf="upload_progress.enabled=On, serialize_handler=${e_ser:-?} (runtime ini_set or another pool may use a different handler)" ;;
                esac
            else
                PRE=ruled_out
                e_surf="upload_progress.enabled=Off, serialize_handler=${e_ser:-?}"
            fi
        fi
    fi
    ev_session_tail 2 "$e_surf" "$OVR_UP" "session.upload_progress.enabled"
}

# CVE-2026-126714 ("phpAfterShell"): files save handler rewritten in place by
# an upload-progress update. Self-contained: does not use ev_session_tail.
#   8.1 and older                              UNKNOWN (EOL mitigation not
#                                              confirmed); NOT_IMPACTED with
#                                              PHP2026_EOL_MITIGATED=1
#   patched                                    NOT_IMPACTED
#   below + files + upload progress on         IMPACTED
#   below + files + upload progress off        UNKNOWN (class is broader)
#   below + other handler / no session ext.    NOT_IMPACTED for a php-fpm ini
#                                              with no save_handler override;
#                                              UNKNOWN otherwise
#   below + handler not readable               UNKNOWN
ev_fileoverwrite() {
    # Tested by series number, not by the fixed-in list. The disclosure: the
    # official 7.4 / 8.0 / 8.1 EOL mitigation branches are not vulnerable (the
    # upload-progress callback returns without opening the session), but
    # "older unpatched 7.4, 8.0, and 8.1 builds retain the original path".
    if [ "$V_MAJ" -lt 8 ] || { [ "$V_MAJ" -eq 8 ] && [ "$V_MIN" -lt 2 ]; }; then
        if [ "${PHP2026_EOL_MITIGATED:-0}" = 1 ]; then
            contrib 4 NOT_IMPACTED "$c_label: series $V_MAJ.$V_MIN declared to carry the official EOL mitigation (PHP2026_EOL_MITIGATED=1; not verified by this script). END-OF-LIFE all the same"
        else
            contrib 4 UNKNOWN "$c_label: series $V_MAJ.$V_MIN is end-of-life: only builds from the official EOL mitigation branches (or a vendor backport) are not vulnerable, older unpatched builds are, and the version number does not show which -- confirm, then set PHP2026_EOL_MITIGATED=1"
        fi
        return 0
    fi
    case "$G_STATE" in
        ok) contrib 4 NOT_IMPACTED "$c_label: patched ($G_WHY)"; return 0 ;;
        below) : ;;
        *) contrib 4 UNKNOWN "$c_label: version gate undecided (${G_NOTE:-$G_WHY})"; return 0 ;;
    esac
    if [ "$c_info_ok" -ne 1 ]; then
        contrib 4 UNKNOWN "$c_label: $G_WHY; no usable '-i' output -- session.save_handler and upload progress not readable (files + upload progress on are the defaults); audit this SAPI's ini by hand"
        return 0
    fi
    e_pre=other
    if ! ini_has session.save_handler; then
        e_surf="no session extension in this configuration"
    else
        e_sh=$(lower "$(ini_get session.save_handler)")
        e_up=$(ini_get session.upload_progress.enabled)
        if is_on "$e_up"; then e_upd=On; elif [ -z "$e_up" ]; then e_upd="?"; else e_upd=Off; fi
        case "$e_sh" in
            files)
                if [ "$e_upd" = Off ]; then e_pre=reduced; else e_pre=met; fi
                e_surf="save_handler=files; upload_progress.enabled=$e_upd" ;;
            '')
                e_pre=unread
                e_surf="session.save_handler not readable (files is the default); upload_progress.enabled=$e_upd" ;;
            *)
                e_surf="save_handler=$e_sh (not files; this CVE is files-specific); upload_progress.enabled=$e_upd" ;;
        esac
    fi
    case "$e_pre" in
        met)
            if [ "$e_upd" = On ]; then
                contrib 4 IMPACTED "$c_label: $G_WHY; files handler + upload-progress writer enabled ($e_surf); no application gadget chain needed"
            else
                contrib 4 IMPACTED "$c_label: $G_WHY; files handler, upload progress not readable (On is the default; not ruled out) ($e_surf)"
            fi ;;
        reduced)
            contrib 4 UNKNOWN "$c_label: $G_WHY; $e_surf -- demonstrated vector removed (vendor temporary mitigation), but the advisory says the issue class is not limited to upload progress: NEEDS-REVIEW. STILL UNPATCHED" ;;
        unread)
            contrib 4 UNKNOWN "$c_label: $G_WHY; $e_surf -- cannot decide; read this SAPI's ini by hand" ;;
        *)
            if [ "$c_sapi" = fpm-fcgi ] && [ "$OVR_SH" -eq 0 ]; then
                N_CFG_ONLY=$((N_CFG_ONLY + 1))
                contrib 4 NOT_IMPACTED "$c_label: $G_WHY, but this php-fpm configuration does not use the files handler and no override was found ($e_surf). STILL UNPATCHED"
            elif [ "$c_sapi" = fpm-fcgi ]; then
                contrib 4 UNKNOWN "$c_label: $G_WHY; base ini does not use the files handler ($e_surf), but a pool / web-server / app override (php_value, .htaccess, .user.ini, ini_set) touches session.save_handler -- review"
            else
                contrib 4 UNKNOWN "$c_label: $G_WHY; files handler ruled out only in this ${c_sapi:-unidentified} ini ($e_surf), which is not the web SAPI configuration -- cannot decide"
            fi ;;
    esac
    return 0
}

# Startup-diagnostic evidence for 129496 (advisory; never decides the status).
ev_tz_startup() {  # version-output error_log-value
    e_diag=$(printf '%s\n' "$1" | tr -d '\r' | grep -E '^(PHP )?(Warning|Notice|Deprecated|Fatal error|Parse error): ' | sed -n '1p' | cut -c1-160)
    if [ -n "$e_diag" ]; then
        cnote 3 "$c_label: ELEVATED -- this binary prints a startup diagnostic every time it starts: $e_diag"
    fi
    e_eff=$(ini_get date.timezone)
    e_cfg=""; e_src=""
    e_main=$(ini_get "Loaded Configuration File")
    e_dir=$(ini_get "Scan this dir for additional .ini files")
    [ -n "$e_dir" ] && [ -d "$e_dir" ] || e_dir=/nonexistent-ini-scan-dir
    for e_f in "$e_main" "$e_dir"/*.ini; do
        [ -n "$e_f" ] && [ -f "$e_f" ] || continue
        e_v2=$(ini_file_last date.timezone "$e_f")
        if [ -n "$e_v2" ]; then e_cfg=$e_v2; e_src=$e_f; fi
    done
    case "$e_cfg" in
        ''|*'$'*) : ;;
        *)
            if [ "$(lower "$e_cfg")" != "$(lower "$e_eff")" ]; then
                cnote 3 "$c_label: ELEVATED -- date.timezone = '$e_cfg' in $e_src was not accepted (effective: '${e_eff:-unset}'); an invalid date.timezone is the advisory's confirmed startup diagnostic"
            fi ;;
    esac
    if is_file_log "$2" && [ -f "$2" ] && [ -r "$2" ]; then
        e_n=$(tail -n 5000 "$2" 2>/dev/null | grep -c -E 'PHP Startup|Invalid date\.timezone' 2>/dev/null)
        is_uint "${e_n:-}" || e_n=0
        if [ "$e_n" -gt 0 ]; then
            cnote 3 "$c_label: ELEVATED -- $2 holds $e_n startup-diagnostic line(s) in its last 5000 lines"
        fi
    fi
    return 0
}

# CVE-2026-129496: NTS build AND PHP's error_log names a file.
ev_tzcache() {
    case "$G_STATE" in
        ok) contrib 3 NOT_IMPACTED "$c_label: patched ($G_WHY)"; return 0 ;;
        below) : ;;
        *) contrib 3 UNKNOWN "$c_label: version gate undecided (${G_NOTE:-$G_WHY})"; return 0 ;;
    esac
    if [ "$c_zts" = ZTS ]; then
        contrib 3 NOT_IMPACTED "$c_label: $G_WHY, but a thread-safe (ZTS) build; this CVE affects NTS builds only. STILL UNPATCHED"
        return 0
    fi
    e_thr="NTS build"
    [ -n "$c_zts" ] || e_thr="thread safety not determined (NTS not ruled out)"
    e_el=""
    if [ "$c_info_ok" -eq 1 ]; then
        e_el=$(ini_get error_log)
        if is_file_log "$e_el"; then e_log=file; else e_log=nofile; fi
    else
        e_log=unseen
    fi
    case "$e_log" in
        file)
            contrib 3 IMPACTED "$c_label: $G_WHY; $e_thr + error_log is a FILE ($e_el)" ;;
        unseen)
            contrib 3 IMPACTED "$c_label: $G_WHY; $e_thr; error_log not readable (no usable '-i' output) -- precondition not ruled out" ;;
        *)
            if [ -n "$WEB_FILE_LOG" ]; then
                contrib 3 IMPACTED "$c_label: $G_WHY; $e_thr; error_log=${e_el:-(unset)} in this ini, but a web-side config sets a FILE error_log"
            elif [ "$c_sapi" = fpm-fcgi ]; then
                N_CFG_ONLY=$((N_CFG_ONLY + 1))
                contrib 3 NOT_IMPACTED "$c_label: $G_WHY, but error_log=${e_el:-(unset)} is not PHP's file-based log path (FPM's own log does not count). STILL UNPATCHED"
            else
                contrib 3 UNKNOWN "$c_label: $G_WHY; $e_thr; error_log=${e_el:-(unset)} in THIS ${c_sapi:-unidentified} ini only -- the web SAPI's error_log was not seen"
            fi ;;
    esac
    [ "$c_info_ok" -eq 1 ] && ev_tz_startup "$c_vout" "$e_el"
    return 0
}

# CVE-2026-129481: 8.3-8.5 below the fix; no ini gate.
ev_shutdown() {
    if [ "$V_MAJ" -eq 8 ] && [ "$V_MIN" -eq 2 ]; then
        contrib 5 NOT_APPLICABLE "$c_label: the 8.2 branch is not affected by this CVE"
        return 0
    fi
    case "$G_STATE" in
        ok) contrib 5 NOT_IMPACTED "$c_label: patched ($G_WHY)" ;;
        below)
            e_ctx=""
            if [ "$c_info_ok" -eq 1 ]; then
                e_sh=$(ini_get session.save_handler)
                e_ctx="; session.save_handler=${e_sh:-not reported}"
                [ "$e_sh" = user ] && e_ctx="$e_ctx (custom userland handler configured: REVIEW its close/write/destroy paths)"
            fi
            case "$c_sapi" in
                cli|phpdbg) e_ctx="$e_ctx; worker reuse: none for one-shot CLI runs, yes for long-running CLI servers" ;;
                *) e_ctx="$e_ctx; worker reuse: yes" ;;
            esac
            contrib 5 IMPACTED "$c_label: $G_WHY; no ini gate -- the application pattern (session-held resource whose close callback fails fatally) cannot be ruled out from the host (NEEDS-REVIEW)$e_ctx" ;;
        *) contrib 5 UNKNOWN "$c_label: version gate undecided (${G_NOTE:-$G_WHY})" ;;
    esac
}

# CVE-2026-129474: 8.5 AND zend.exception_ignore_args=0 AND
# fatal_error_backtraces != 0.
ev_backtrace() {
    case "$G85" in
        na) contrib 6 NOT_APPLICABLE "$c_label: series $V_MAJ.$V_MIN is not affected (PHP 8.5 only)"; return 0 ;;
        ok) contrib 6 NOT_IMPACTED "$c_label: patched (>= $FIXED_85)"; return 0 ;;
        vuln) : ;;
        *) contrib 6 UNKNOWN "$c_label: pre-release build ($V_MAJ.$V_MIN.$V_PAT$V_SUF); not evaluated"; return 0 ;;
    esac
    if [ "$c_info_ok" -eq 0 ]; then
        contrib 6 IMPACTED "$c_label: < $FIXED_85; gate not readable (no usable '-i' output) -- the 8.5 compiled-in defaults are the vulnerable combination"
        return 0
    fi
    # A directive missing from "-i" falls back to the 8.5 compiled-in default.
    if ini_has zend.exception_ignore_args; then e_eia=$(ini_get zend.exception_ignore_args); else e_eia=Off; fi
    if ini_has fatal_error_backtraces; then e_feb=$(ini_get fatal_error_backtraces); else e_feb=On; fi
    is_on "$e_eia" && e_eia=On || e_eia=Off
    is_on "$e_feb" && e_feb=On || e_feb=Off
    e_web=""
    [ "$c_sapi" = fpm-fcgi ] || e_web=" -- read from the ${c_sapi:-unknown-SAPI} ini only; this does NOT show what the web SAPI loads"
    if [ "$e_eia" = On ]; then
        N_CFG_ONLY=$((N_CFG_ONLY + 1))
        contrib 6 NOT_IMPACTED "$c_label: < $FIXED_85, but zend.exception_ignore_args=On prevents the attack path. STILL UNPATCHED$e_web"
    elif [ "$e_feb" = Off ]; then
        N_CFG_ONLY=$((N_CFG_ONLY + 1))
        contrib 6 NOT_IMPACTED "$c_label: < $FIXED_85, but fatal_error_backtraces=Off. STILL UNPATCHED$e_web"
    else
        contrib 6 IMPACTED "$c_label: < $FIXED_85; zend.exception_ignore_args=Off + fatal_error_backtraces=On (gate open)"
    fi
}

# CVE-2026-129182: 8.5 AND a per-directory / per-request INI override.
ev_backtrace_shutdown() {
    case "$G85" in
        na) contrib 7 NOT_APPLICABLE "$c_label: series $V_MAJ.$V_MIN is not affected (PHP 8.5 only)" ;;
        ok) contrib 7 NOT_IMPACTED "$c_label: patched (>= $FIXED_85)" ;;
        vuln)
            if [ "$N_SURF" -gt 0 ]; then
                contrib 7 IMPACTED "$c_label: < $FIXED_85; $N_SURF per-directory / per-request INI override line(s) on this host: $SURF_TXT (whether they conflict is not decided)"
            else
                contrib 7 UNKNOWN "$c_label: < $FIXED_85; no php_value / PHP_VALUE override found in the scanned locations -- not proven absent (set PHP2026_APP_PATH / PHP2026_WEB_CONF_DIRS)"
            fi ;;
        *) contrib 7 UNKNOWN "$c_label: pre-release build ($V_MAJ.$V_MIN.$V_PAT$V_SUF); not evaluated" ;;
    esac
}

J_INSTALLS=""

check_php() {  # run-path label resolved-path
    c_bin=$1; c_label=$2; c_real=$3

    c_vout=$(probe_all "$c_bin" -v)
    c_vtok=$(printf '%s\n' "$c_vout" | sed -n 's/^PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][^ ]*\).*/\1/p' | sed -n 1p)
    c_sapi=$(printf '%s\n' "$c_vout" | sed -n 's/^PHP [0-9][^ ]* (\([^)]*\)).*/\1/p' | sed -n 1p)
    c_zts=""
    case "$c_vout" in
        *"(ZTS"*|*" ZTS "*) c_zts=ZTS ;;
        *"(NTS"*|*" NTS "*) c_zts=NTS ;;
    esac

    # php -i: keep only the lines the gates read. php-cgi prints HTML here.
    INFO=""
    c_info_ok=0
    c_iout=$(probe "$c_bin" -i)
    case "$c_iout" in
        *"<html"*|*"<HTML"*|*"<!DOCTYPE"*) : ;;
        *"PHP Version => "*)
            c_info_ok=1
            INFO=$(printf '%s\n' "$c_iout" | tr -d '\r' | grep -E '^(session\.|Session Support =>|opcache\.enable =>|opcache\.enable_cli =>|error_log =>|date\.timezone =>|zend\.exception_ignore_args =>|fatal_error_backtraces =>|memory_limit =>|Thread Safety =>|Server API =>|PHP Version =>|Loaded Configuration File =>|Scan this dir for additional \.ini files =>)') ;;
    esac
    c_iout=""

    if [ "$c_info_ok" -eq 1 ]; then
        [ -n "$c_vtok" ] || c_vtok=$(ini_get "PHP Version")
        case "$(lower "$(ini_get "Thread Safety")")" in
            enabled) c_zts=ZTS ;;
            disabled) c_zts=NTS ;;
        esac
        if [ -z "$c_sapi" ]; then
            case "$(ini_get "Server API")" in
                "Command Line Interface") c_sapi=cli ;;
                FPM/FastCGI) c_sapi=fpm-fcgi ;;
                CGI/FastCGI) c_sapi=cgi-fcgi ;;
                "Apache 2"*) c_sapi=apache2handler ;;
                *FrankenPHP*|*frankenphp*) c_sapi=frankenphp ;;
            esac
        fi
    fi
    # A binary reached through a master's /proc entry is php-fpm by definition.
    case "$c_label" in
        "php-fpm pid "*) [ -n "$c_sapi" ] || c_sapi=fpm-fcgi ;;
    esac

    if [ -z "$c_vtok" ] || ! parse_version "$c_vtok"; then
        irow "$c_label" "?" "${c_sapi:-?}" "${c_zts:-?}" "version not parseable (not a PHP binary, or it failed to run)"
        contrib_all UNKNOWN "$c_label: version not parseable (not a PHP binary, or it failed to run)"
        J_INSTALLS="$J_INSTALLS${J_INSTALLS:+,}{\"path\":\"$(json_esc "$c_label")\",\"version\":null,\"sapi\":null,\"zts\":null}"
        return 0
    fi

    case "$c_sapi" in
        cli|phpdbg) c_sdisp=$c_sapi; N_CLI_ROWS=$((N_CLI_ROWS + 1)) ;;
        fpm-fcgi) c_sdisp="fpm(web)" ;;
        cgi-fcgi) c_sdisp="cgi(web)" ;;
        '') c_sdisp="?" ;;
        *) c_sdisp=$c_sapi ;;
    esac
    [ "$c_info_ok" -eq 1 ] && [ "$c_sapi" = fpm-fcgi ] && N_FPM_EVAL=$((N_FPM_EVAL + 1))

    gate_std
    gate_85
    [ "$G85" = vuln ] && N_VULN85=$((N_VULN85 + 1))
    c_ver="$V_MAJ.$V_MIN.$V_PAT$V_SUF"

    irow "$c_label" "$c_ver" "$c_sdisp" "${c_zts:-?}" "$G_WHY"
    [ -n "$G_NOTE" ] && say "       note: $G_NOTE"
    [ "$c_info_ok" -eq 1 ] || say "       note: no usable '-i' output; ini-gated checks fall back to 'not ruled out' -- audit this SAPI's ini by hand"
    if [ "$G_STATE" = below ]; then
        N_BELOW=$((N_BELOW + 1))
        if [ "$QUIET" -eq 0 ] && [ "$JSON" -eq 0 ]; then
            pkg_owner "$c_real"
            if [ -n "$PKG" ]; then
                say "       note: distribution package ($PKG): vendors may backport the fix without changing the upstream version -- confirm against the distribution's security tracker"
            fi
        fi
    fi
    if [ "$c_info_ok" -eq 1 ]; then
        c_ini=$(ini_get "Loaded Configuration File")
        case "$c_sapi" in
            fpm-fcgi) vsay "       ini:  ${c_ini:-(none)}  [php-fpm base ini; pool php_value/php_admin_value NOT applied]" ;;
            cli) vsay "       ini:  ${c_ini:-(none)}  [CLI ini -- NOT the web SAPI configuration]" ;;
            *) vsay "       ini:  ${c_ini:-(none)}" ;;
        esac
    fi
    J_INSTALLS="$J_INSTALLS${J_INSTALLS:+,}{\"path\":\"$(json_esc "$c_label")\",\"version\":\"$(json_esc "$c_ver")\",\"sapi\":\"$(json_esc "${c_sapi:-}")\",\"zts\":\"${c_zts:-}\"}"

    ev_fpm
    ev_serializer
    ev_tzcache
    ev_fileoverwrite
    ev_shutdown
    ev_backtrace
    ev_backtrace_shutdown
    return 0
}

# mod_php and FrankenPHP cannot be queried from the command line. A web
# runtime that was not evaluated keeps the CVEs it could carry at UNKNOWN.
# (129289 needs the FPM SAPI and is not touched.)
N_EMBED=0
scan_embedded() {
    for se in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so \
              /usr/lib/httpd/modules/libphp*.so /etc/httpd/modules/libphp*.so \
              /usr/lib64/apache2/modules/libphp*.so /usr/libexec/apache2/libphp*.so \
              /usr/local/lib/httpd/modules/libphp*.so /opt/homebrew/lib/httpd/modules/libphp*.so \
              /usr/local/apache2/modules/libphp*.so /usr/local/libexec/apache2*/libphp*.so; do
        [ -e "$se" ] || continue
        N_EMBED=$((N_EMBED + 1))
        se_v=${se##*/libphp}
        se_v=${se_v%.so}
        case "$se_v" in
            [0-9].[0-9]|[0-9].[0-9][0-9]) : ;;
            *) se_v="" ;;
        esac
        arow "web SAPI (mod_php)" "not evaluated: $se -- check its version and ini over HTTP (phpinfo behind auth) or via the package version"
        for se_i in 2 3 4 5 6 7; do
            # the file name can rule a series out for the branch-limited CVEs
            case "$se_i" in
                5) [ "$se_v" = "8.2" ] && continue ;;
                6|7) [ -n "$se_v" ] && [ "$se_v" != "8.5" ] && continue ;;
            esac
            contrib "$se_i" UNKNOWN "mod_php $se: not evaluated (cannot be queried from the command line)"
        done
    done
    if [ -n "$FRANKEN" ]; then
        N_EMBED=$((N_EMBED + 1))
        arow "web SAPI (FrankenPHP)" "not evaluated: $FRANKEN embeds its own (thread-safe) PHP -- check its PHP version and ini by hand"
        # FrankenPHP is a ZTS build, which 129496 does not affect.
        for se_i in 2 4 5 6 7; do
            contrib "$se_i" UNKNOWN "FrankenPHP $FRANKEN: not evaluated (embeds its own PHP)"
        done
    fi
}

# --------------------------------------------------------------------- main

HOST_LABEL=$(hostname 2>/dev/null) || HOST_LABEL=""
[ -n "$HOST_LABEL" ] || HOST_LABEL=$(uname -n 2>/dev/null) || HOST_LABEL=""
[ -n "$HOST_LABEL" ] || HOST_LABEL=${HOSTNAME:-unknown-host}

say "PHP criticals 2026-11-19 exposure check  (7 CVEs; fixed-in: $FIXED_IN)"
say "host: $HOST_LABEL"

# Host-wide signals first: every install is evaluated against them.
gather_web
scan_frontend

say "php installs:"

# Binaries named with -b are always reported, even when unusable.
OLDIFS=$IFS
IFS=$NL
set -f
for xb in $EXTRA_BINS; do
    IFS=$OLDIFS
    set +f
    if [ -f "$xb" ] && [ -x "$xb" ]; then
        add_cand "$xb"
    else
        irow "$xb" "?" "?" "?" "not an executable file (-b)"
        contrib_all UNKNOWN "$xb: not an executable file (-b)"
    fi
done
IFS=$OLDIFS
set +f

discover
scan_procs

OLDIFS=$IFS
IFS=$NL
set -f
for cl in $CANDS; do
    IFS=$OLDIFS
    set +f
    cl_bin=${cl%%"$TAB"*}
    cl_rest=${cl#*"$TAB"}
    cl_label=${cl_rest%%"$TAB"*}
    cl_real=${cl_rest#*"$TAB"}
    check_php "$cl_bin" "$cl_label" "$cl_real"
done
IFS=$OLDIFS
set +f

if [ -z "$CANDS" ]; then
    say "  [?]  no php / php-fpm binary found on PATH or in common install directories (use -b PATH)"
fi

# ---- host-level results

# A running php-fpm master whose binary could not be read is an install that
# was not evaluated.
if [ "$N_PROC_UNSEEN" -gt 0 ]; then
    contrib_all UNKNOWN "$N_PROC_UNSEEN running php-fpm master(s) whose binary could not be read -- version NOT checked (run as root)"
fi

# 129289 on a host with a vulnerable PHP but no php-fpm at all: the CVE needs
# the FPM SAPI, so it is ruled out unless a local front end keeps FastCGI /
# LSAPI connections open to a backend this script did not find.
if [ "$N_FPM_ROWS" -eq 0 ] && [ "$N_MASTERS" -eq 0 ] && [ "$N_NONFPM_VULN" -gt 0 ]; then
    if [ "$FE_STATE" = reuse ] || [ -n "$FE_OTHER" ]; then
        contrib 1 UNKNOWN "vulnerable PHP version and a front end that keeps FastCGI/LSAPI connections open, but no php-fpm was found on this host -- locate the PHP backend it talks to and run this script there"
    else
        contrib 1 NOT_IMPACTED "no php-fpm binary and no running php-fpm master: this CVE needs the FPM SAPI (the PHP found is still below the fixed release)"
    fi
fi
cnote 1 "application routes that do not read the request body: assumed present (not checked)"

scan_embedded

# 129474: an override that turns zend.exception_ignore_args off opens the
# gate in its scope, whatever the binary's own ini says.
if [ -n "$EIA_OPEN" ]; then
    if [ "$N_VULN85" -gt 0 ]; then
        contrib 6 IMPACTED "$(count_lines "$EIA_OPEN") web-side line(s) turn zend.exception_ignore_args off on a host with an unpatched PHP 8.5 -- gate open in that scope: $(printf '%s\n' "$EIA_OPEN" | sed -n 1p | cut -c1-160)"
    else
        cnote 6 "$(count_lines "$EIA_OPEN") web-side line(s) turn zend.exception_ignore_args off; no unpatched PHP 8.5 binary was seen, so not counted"
    fi
fi
[ -n "$EIA_REST" ] && cnote 6 "$(count_lines "$EIA_REST") other pool / web-server / per-directory line(s) set zend.exception_ignore_args or fatal_error_backtraces -- effective web config differs from '-i'; not merged"

# Advisory context for the other gates.
[ -n "$FE_SURF" ] && cnote 1 "front-end config: $(printf '%s' "$FE_SURF" | tr '\n' '|' | sed -e 's/|$//' -e 's/|/ | /g')"
case "$POOL_STATE" in
    local) cnote 1 "php-fpm pools listen on unix sockets / loopback only" ;;
    remote) cnote 1 "a php-fpm pool is reachable beyond loopback or unreadable -- a front end on another host may connect: $(printf '%s' "$POOL_REMOTE" | sed -n 1p)" ;;
esac
if [ -n "$SESS_HITS" ]; then
    cnote 2 "$(count_lines "$SESS_HITS") pool / web-server / per-directory line(s) override session settings -- effective web config differs from '-i'; not merged"
    cnote 4 "$(count_lines "$SESS_HITS") pool / web-server / per-directory line(s) override session settings -- effective web config differs from '-i'; not merged"
    if printf '%s\n' "$SESS_HITS" | grep -Eiq 'session\.serialize_handler[]"'"'"']*[[:space:]]*=?[[:space:]]*"?(php_serialize|php_binary)'; then
        cnote 2 "an override sets session.serialize_handler to php_serialize / php_binary: config precondition MET in that scope if upload progress is on"
    fi
fi
case "$SEEN_SER" in
    *" "*) cnote 2 "mixed serialize handlers on this host ($SEEN_SER) -- the mismatch condition if those contexts share one session store" ;;
esac
[ -n "$APP_SER" ] && cnote 2 "app path: $(count_lines "$APP_SER") file(s) set session.serialize_handler at runtime (ini_set / session_start option) -- the documented mismatch path"
[ -n "$WEB_FILE_LOG" ] && cnote 3 "web-side error_log names a FILE: $(printf '%s\n' "$WEB_FILE_LOG" | sed -n '1,3p' | tr '\n' '|' | sed -e 's/|$//' -e 's/|/ | /g')"
[ -n "$WEB_TZ" ] && cnote 3 "ELEVATED? web-side date.timezone not found in /usr/share/zoneinfo: $(printf '%s\n' "$WEB_TZ" | sed -n '1,3p' | tr '\n' '|' | sed -e 's/|$//' -e 's/|/ | /g')"
[ -n "$APP_H1" ] && cnote 5 "app path (H1): $(count_lines "$APP_H1") file(s) with a custom session save handler -- REVIEW: can close() / write() / destroy() end in a fatal error?"
[ -n "$APP_H2" ] && cnote 5 "app path (H2): $(count_lines "$APP_H2") file(s) with a userland stream wrapper -- REVIEW: is such a stream kept in the session, and can stream_close() fail fatally?"
[ -n "$APP_H3" ] && cnote 5 "app path (H3): $(count_lines "$APP_H3") file(s) assign a resource straight into \$_SESSION -- the session-held resource of the advisory"
if [ -n "$APP_PATH" ] && [ "$APP_BAD" -eq 0 ] && [ -z "$APP_H1$APP_H2$APP_H3" ]; then
    cnote 5 "app path: no custom session handler, userland stream wrapper or resource-in-\$_SESSION pattern found; this lowers the likelihood, it does NOT clear the status"
fi
[ -n "$S_CONFLICT" ] && cnote 7 "$(count_lines "$S_CONFLICT") override line(s) touch the settings named in the advisory (max_memory_limit / memory_limit / zlib.output_compression / output_handler): $(printf '%s\n' "$S_CONFLICT" | sed -n 1p | cut -c1-160)"
[ -n "$UINI_FILES" ] && cnote 7 "$(count_lines "$UINI_FILES") .user.ini file(s): path-specific INI as well; advisory, not counted"
[ -n "$S_POOL" ] && cnote 7 "$(count_lines "$S_POOL") php-fpm pool line(s) set memory_limit / output settings: one side of a possible conflict; advisory"

# ---- notes

if [ "$QUIET" -eq 0 ] && [ "$JSON" -eq 0 ]; then
    if [ "$N_FPM_EVAL" -eq 0 ]; then
        arow "web SAPI (php-fpm)" "not evaluated -- no php-fpm binary answered '-i'; audit the web SAPI's version and ini by hand"
    fi
    if [ -n "$PROC_NOTES" ]; then
        printf '%s' "$PROC_NOTES" | sed 's/^/       note: /'
    fi
    if [ "$APP_BAD" -eq 1 ]; then
        arow "app path" "PHP2026_APP_PATH is not a readable directory: $APP_PATH"
    fi
    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        say "       note: not running as root -- config files, web roots and processes this user cannot read were skipped"
    fi
    say ""
fi

# ---- per-CVE status lines

N_I=0; N_U=0; N_N=0; N_A=0
J_CVES=""
for i in 1 2 3 4 5 6 7; do
    eval "p_st=\$ST_$i; p_fd=\$FIND_$i"
    if [ -z "$p_st" ]; then
        p_st=UNKNOWN
        if [ -z "$CANDS" ]; then
            p_fd="[UNKNOWN] no PHP install found on this host$NL$p_fd"
        else
            p_fd="[UNKNOWN] no PHP install on this host could be evaluated for this CVE$NL$p_fd"
        fi
    fi
    case "$p_st" in
        IMPACTED) N_I=$((N_I + 1)) ;;
        UNKNOWN) N_U=$((N_U + 1)) ;;
        NOT_IMPACTED) N_N=$((N_N + 1)) ;;
        *) N_A=$((N_A + 1)) ;;
    esac
    p_fd=${p_fd%"$NL"}
    if [ "$JSON" -eq 1 ]; then
        p_jf=""
        OLDIFS=$IFS
        IFS=$NL
        set -f
        for p_l in $p_fd; do
            p_jf="$p_jf${p_jf:+,}\"$(json_esc "$p_l")\""
        done
        IFS=$OLDIFS
        set +f
        J_CVES="$J_CVES${J_CVES:+,}{\"id\":\"$(cve_id $i)\",\"status\":\"$p_st\",\"name\":\"$(json_esc "$(cve_name $i)")\",\"findings\":[$p_jf],\"mitigation\":\"$(json_esc "$(cve_fix $i)")\"}"
    else
        printf '%-15s  %-12s  %s\n' "$(cve_id $i)" "$p_st" "$(cve_name $i)"
        if [ "$QUIET" -eq 0 ] && [ "$VERBOSE" -eq 1 ]; then
            [ -n "$p_fd" ] && printf '%s\n' "$p_fd" | sed 's/^/    gate: /'
            printf '    fix:  %s\n' "$(cve_fix $i)"
        fi
    fi
done

if [ "$N_I" -gt 0 ]; then
    VERDICT="impacted"; RC=1
elif [ "$N_U" -gt 0 ]; then
    VERDICT="unknown"; RC=2
else
    VERDICT="not impacted"; RC=0
fi
COUNTS="impacted: $N_I  unknown: $N_U  not impacted: $N_N  not applicable: $N_A"

if [ "$JSON" -eq 1 ]; then
    printf '{"tool":"detect-php-criticals","host":"%s","fixed_in":"%s","installs":[%s],"cves":[%s],"counts":{"impacted":%s,"unknown":%s,"not_impacted":%s,"not_applicable":%s},"overall":"%s","exit_code":%s}\n' \
        "$(json_esc "$HOST_LABEL")" "$(json_esc "$FIXED_IN")" "$J_INSTALLS" "$J_CVES" \
        "$N_I" "$N_U" "$N_N" "$N_A" "$VERDICT" "$RC"
elif [ "$QUIET" -eq 0 ]; then
    say ""
    say "WARNING: CLI ini != web SAPI ini."
    if [ "$N_CLI_ROWS" -gt 0 ] || [ "$N_FPM_EVAL" -eq 0 ]; then
        say "  A cli row describes the COMMAND-LINE binary and configuration only. The web"
        say "  SAPI (php-fpm / mod_php / FrankenPHP) can be a different PHP build and loads"
        say "  its own php.ini plus pool php_value/php_admin_value, .htaccess php_value,"
        say "  .user.ini and fastcgi_param PHP_VALUE. The risky settings often live only"
        say "  there. Audit it separately."
    fi
    if [ "$N_FPM_EVAL" -gt 0 ]; then
        say "  fpm(web) rows use 'php-fpm -i' (the FPM base php.ini). Per-pool, per-directory"
        say "  and per-request overrides are searched for but are NOT merged in."
    fi
    if [ "$N_CFG_ONLY" -gt 0 ]; then
        say "  $N_CFG_ONLY NOT_IMPACTED result(s) rest on configuration alone for a PHP that is"
        say "  still below the fixed release. That lasts exactly as long as the setting does."
    fi
    if [ "$N_BELOW" -gt 0 ]; then
        say "  IMPACTED = below the fixed release AND the CVE's precondition is met or cannot"
        say "  be ruled out from this host. Update to $FIXED_IN (per series)"
        say "  and restart php-fpm / the web server. Gate findings and mitigations: -v"
    fi
    say "overall: $VERDICT  ($COUNTS)"
fi

echo "$VERDICT"
exit "$RC"
