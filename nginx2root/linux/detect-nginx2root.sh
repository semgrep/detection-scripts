#!/usr/bin/env bash
set -u
set -f

FIXED_IN="${NGINX2ROOT_FIXED_IN-1.30.7 1.31.9}"
FIXED_PKGS="${NGINX2ROOT_FIXED_PKGS:-}"

ID1=CVE-2026-123007
ID2=CVE-2026-123633
ID3=CVE-2026-121810
ID4=CVE-2026-123634
ID5=CVE-2026-113425

QUIET=0
VERBOSE=0
SCAN_PROCS=1
SCAN_DISK=1
SCAN_KERNEL=1
EXTRA_BINS=""
CONF_OPT=""
ROOT_OPT=""

usage() {
    cat <<'EOF'
usage: detect-nginx2root.sh [-q] [-v] [-b /path/to/nginx]... [-c /path/to/nginx.conf]
                            [-r /path/to/rootfs] [--no-procs] [--no-disk] [--no-kernel]

  -q, --quiet       print only the per-CVE status lines and the verdict
  -v, --verbose     print diagnostic detail
  -b, --binary PATH also check this nginx binary (repeatable)
  -c, --conf PATH   configuration file to use for binaries that are not
                    running (those from -b and from the disk scan)
  -r, --root DIR    -b and -c paths are inside DIR, an unpacked image or a
                    mounted disk; packages and includes are read from there
  --no-procs        skip running processes
  --no-disk         skip installed binaries on disk
  --no-kernel       skip the host kernel SCTP line

Exit: 0 not impacted, 1 impacted, 2 unknown, 3 usage error.
Env:  NGINX2ROOT_FIXED_IN="1.30.7 1.31.9"      first fixed nginx releases
      NGINX2ROOT_FIXED_PKGS="name=version ..." packages confirmed as fixed
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -q|--quiet) QUIET=1 ;;
        -v|--verbose) VERBOSE=1 ;;
        -b|--binary)
            [ $# -ge 2 ] || { usage >&2; exit 3; }
            EXTRA_BINS="$EXTRA_BINS$2
"
            shift ;;
        -c|--conf)
            [ $# -ge 2 ] || { usage >&2; exit 3; }
            CONF_OPT="$2"
            shift ;;
        -r|--root)
            [ $# -ge 2 ] || { usage >&2; exit 3; }
            ROOT_OPT="${2%/}"
            [ -d "$ROOT_OPT/" ] || { echo "not a directory: $2" >&2; exit 3; }
            case "$ROOT_OPT" in /*) ;; *) ROOT_OPT="$PWD/$ROOT_OPT" ;; esac
            shift ;;
        --no-procs) SCAN_PROCS=0 ;;
        --no-disk) SCAN_DISK=0 ;;
        --no-kernel) SCAN_KERNEL=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 3 ;;
    esac
    shift
done

if [ -n "$CONF_OPT" ] && [ -z "$ROOT_OPT" ]; then
    case "$CONF_OPT" in /*) ;; *) CONF_OPT="$PWD/$CONF_OPT" ;; esac
fi

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t nginx2root) || { echo unknown; exit 2; }
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/cands"
: > "$TMP/procs"
: > "$TMP/running"
: > "$TMP/draining"

N_IMPACTED=0
N_UNKNOWN=0
N_OK=0

H1=ok
H2=ok
H3=ok
H4=ok
H5=ok

TAB=$(printf '\t')
SEP=$(printf '\037')
NL='
'

GREP_A=""
if printf 'x\n' | grep -a x >/dev/null 2>&1; then GREP_A="-a"; fi

say() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
dbg() { [ "$VERBOSE" -eq 1 ] && printf 'debug: %s\n' "$*" >&2; return 0; }

tally() {
    case "$1" in
        impacted) N_IMPACTED=$((N_IMPACTED + 1)) ;;
        unknown)  N_UNKNOWN=$((N_UNKNOWN + 1)) ;;
        *)        N_OK=$((N_OK + 1)) ;;
    esac
}

word() {
    case "$1" in
        impacted) echo "impacted" ;;
        ok) echo "not impacted" ;;
        unknown) echo "unknown" ;;
        *) echo "not checked" ;;
    esac
}

worse() {
    case "$1:$2" in
        impacted:*|*:impacted) echo impacted ;;
        unknown:*|*:unknown) echo unknown ;;
        *) echo ok ;;
    esac
}

bump() {
    case "$1" in
        1) H1=$(worse "$H1" "$2") ;;
        2) H2=$(worse "$H2" "$2") ;;
        3) H3=$(worse "$H3" "$2") ;;
        4) H4=$(worse "$H4" "$2") ;;
        5) H5=$(worse "$H5" "$2") ;;
    esac
}

bump_all() {
    bump 1 "$1"; bump 2 "$1"; bump 3 "$1"; bump 4 "$1"; bump 5 "$1"
}

line() { say "  $1: $(word "$2")${3:+ ($3)}"; }

result_line() {
    case "$1" in
        impacted) say "  => impacted${2:+ ($2)}" ;;
        ok) say "  => not impacted" ;;
        *) say "  => unknown" ;;
    esac
}

single() {
    say ""
    say "$1"
    say "  $2"
    result_line unknown
    tally unknown
    bump_all unknown
}

header() {
    say "nginx2root check: the five CVEs fixed in nginx 1.31.9 and 1.30.7"
    say "Each nginx gets a status per CVE: impacted, not impacted or unknown (could not check)."
}

finish() {
    local v
    if [ "$N_IMPACTED" -gt 0 ]; then v=impacted
    elif [ "$N_UNKNOWN" -gt 0 ]; then v=unknown
    else v="not impacted"
    fi
    [ $((N_IMPACTED + N_UNKNOWN + N_OK)) -eq 0 ] && { say ""; say "no nginx found"; }
    say ""
    say "this host"
    printf '%s: %s\n' "$ID1" "$(word "$H1")"
    printf '%s: %s\n' "$ID2" "$(word "$H2")"
    printf '%s: %s\n' "$ID3" "$(word "$H3")"
    printf '%s: %s\n' "$ID4" "$(word "$H4")"
    printf '%s: %s\n' "$ID5" "$(word "$H5")"
    say ""
    echo "$v"
    case "$v" in
        impacted) exit 1 ;;
        unknown) exit 2 ;;
    esac
    exit 0
}

clean() { printf '%s' "$1" | LC_ALL=C tr -cd '\040-\176' | cut -c1-160; }

ver_key() {
    local v IFS=.
    v=$(printf '%s' "$1" | sed 's/[^0-9.].*$//')
    set -- $v
    echo $(( 10#${1:-0} * 1000000 + 10#${2:-0} * 1000 + 10#${3:-0} ))
}

is_fixed() {
    local k=$1 f fk top=0
    for f in $FIXED_IN; do
        fk=$(ver_key "$f")
        [ $((fk / 1000)) -gt "$top" ] && top=$((fk / 1000))
        if [ $((fk / 1000)) -eq $((k / 1000)) ] && [ "$k" -ge "$fk" ]; then
            return 0
        fi
    done
    [ "$top" -gt 0 ] && [ $((k / 1000)) -gt "$top" ]
}

LOW1=$(ver_key 1.9.5)
LOW2=$(ver_key 1.19.7)
LOW3=$(ver_key 1.25.0)
LOW4=$(ver_key 0.6.18)
LOW5=$(ver_key 0.5.33)

resolve_in() {
    local root=$1 rest=$2 cur="" comp t n=0
    while [ -n "$rest" ]; do
        comp=${rest%%/*}
        if [ "$comp" = "$rest" ]; then rest=""; else rest=${rest#*/}; fi
        case "$comp" in
            ''|.) continue ;;
            ..) cur=${cur%/*}; continue ;;
        esac
        if [ -L "$root$cur/$comp" ]; then
            n=$((n + 1))
            [ "$n" -gt 40 ] && return 1
            t=$(readlink "$root$cur/$comp") || return 1
            case "$t" in /*) cur="" ;; esac
            rest="$t${rest:+/$rest}"
        else
            cur="$cur/$comp"
        fi
    done
    printf '%s\n' "${cur:-/}"
}

pkg_of() {
    local root=$1 path=$2 l name ver
    [ -n "$path" ] || return 0
    if [ -d "$root/var/lib/dpkg/info" ] && [ -r "$root/var/lib/dpkg/status" ]; then
        set +f
        l=$(grep -lxF -- "$path" "$root"/var/lib/dpkg/info/*.list 2>/dev/null)
        set -f
        l=${l%%"$NL"*}
        if [ -n "$l" ]; then
            name=${l##*/}; name=${name%.list}; name=${name%%:*}
            ver=$(awk -v p="$name" '$1 == "Package:" { n = $2 } $1 == "Version:" && n == p { print $2; exit }' \
                "$root/var/lib/dpkg/status" 2>/dev/null)
            if [ -n "$ver" ]; then printf 'dpkg %s=%s\n' "$name" "$ver"; return 0; fi
        fi
    fi
    if [ -r "$root/lib/apk/db/installed" ]; then
        l=$(awk -v t="${path#/}" '
            { k = substr($0, 1, 2); v = substr($0, 3) }
            k == "P:" { p = v } k == "V:" { ver = v } k == "F:" { d = v }
            k == "R:" && d "/" v == t { print p "=" ver; exit }' "$root/lib/apk/db/installed" 2>/dev/null)
        if [ -n "$l" ]; then printf 'apk %s\n' "$l"; return 0; fi
    fi
    if command -v rpm >/dev/null 2>&1 &&
        { [ -d "$root/var/lib/rpm" ] || [ -d "$root/usr/lib/sysimage/rpm" ]; }; then
        if [ -n "$root" ]; then
            l=$(rpm --root "$root" -qf --qf '%{NAME}=%{VERSION}-%{RELEASE}\n' "$path" 2>/dev/null) || l=""
        else
            l=$(rpm -qf --qf '%{NAME}=%{VERSION}-%{RELEASE}\n' "$path" 2>/dev/null) || l=""
        fi
        l=${l%%"$NL"*}
        case "$l" in
            *" "*|"") ;;
            *=*) printf 'rpm %s\n' "$l"; return 0 ;;
        esac
    fi
    return 0
}

pkg_cves() {
    local root=$1 kind=$2 name=$3 f text="" got=0 id out=""
    case "$kind" in
        dpkg)
            f=$(resolve_in "$root" "/usr/share/doc/$name/changelog.Debian.gz") || f=""
            if [ -n "$f" ] && [ -r "$root$f" ] && command -v gzip >/dev/null 2>&1; then
                text=$(gzip -dc < "$root$f" 2>/dev/null | grep -o -E 'CVE-2026-[0-9]+' 2>/dev/null) && got=1
                [ -n "$text" ] || got=1
            fi ;;
        rpm)
            if command -v rpm >/dev/null 2>&1; then
                if [ -n "$root" ]; then
                    text=$(rpm --root "$root" -q --changelog "$name" 2>/dev/null) && got=1
                else
                    text=$(rpm -q --changelog "$name" 2>/dev/null) && got=1
                fi
            fi ;;
    esac
    if [ "$got" -eq 0 ]; then echo "-"; return 0; fi
    for id in "$ID1" "$ID2" "$ID3" "$ID4" "$ID5"; do
        case "$text" in *"$id"*) out="$out $id" ;; esac
    done
    echo "${out# }"
}

pkg_fixed() {
    local kind=$1 pkg=$2 e
    [ -n "$pkg" ] || return 1
    for e in $FIXED_PKGS; do
        [ "${e%%=*}" = "${pkg%%=*}" ] || continue
        [ "${e#*=}" = "${pkg#*=}" ] && return 0
        if [ "$kind" = dpkg ] && command -v dpkg >/dev/null 2>&1 &&
            dpkg --compare-versions "${pkg#*=}" ge "${e#*=}" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

bin_info() {
    local f=$1 s l rest
    B_VERLINE=""; B_PRODUCT=""; B_VERSION=""; B_BUILD=""; B_ALT=""
    B_CONFARGS=""; B_MARK_OLD=0; B_MARK_NEW=0
    [ -r "$f" ] || return 1
    s=$(tr '\0' '\n' < "$f" 2>/dev/null | LC_ALL=C grep $GREP_A -o -E \
        '[A-Za-z]+ version: [A-Za-z]+/[0-9][0-9.]*[ -~]*|configure arguments:[ -~]*|could not cancel %V resolving|mail auth http block write|smtp writing blocked' \
        2>/dev/null) || s=""
    while IFS= read -r l; do
        case "$l" in
            "could not cancel %V resolving") B_MARK_OLD=1 ;;
            "mail auth http block write"|"smtp writing blocked") B_MARK_NEW=1 ;;
            "configure arguments:"*) [ -n "$B_CONFARGS" ] || B_CONFARGS=" ${l#configure arguments:} " ;;
            "nginx version: "*) B_VERLINE=$l ;;
            *" version: "*)
                [ -n "$B_ALT" ] || B_ALT=${l#* version: }
                [ -n "$B_VERLINE" ] || B_VERLINE=$l ;;
        esac
    done <<EOF
$s
EOF
    [ -n "$B_VERLINE" ] || return 0
    rest=${B_VERLINE#* version: }
    B_PRODUCT=${rest%%/*}
    B_VERSION=${rest#*/}
    case "$B_VERSION" in *" "*) B_BUILD=" ${B_VERSION#* }"; B_VERSION=${B_VERSION%% *} ;; esac
    case "$B_ALT" in "$rest"|"") B_ALT="" ;; esac
    return 0
}

built() {
    [ -n "$B_CONFARGS" ] || return 0
    printf '%s\n' "$B_CONFARGS" | grep -qE -- "$1"
}

conf_arg() {
    printf '%s\n' "$B_CONFARGS" | sed -n "s/.* --$1=\([^ ]*\) .*/\1/p"
}

CONF_PARTIAL=0
CONF_FILES=0
CONF_SEQ=0

tokenize() {
    awk '
    function emit(t,    i, s, w) {
        s = t "\t"
        for (i = 1; i <= n; i++) {
            w = A[i]
            gsub(/[^ -~]/, "?", w)
            if (i > 1) s = s US
            s = s w
        }
        print s
        if (t == "{" && n > 0 && A[1] ~ /_by_lua_block$/) { raw = 1; rawdepth = 1 }
        n = 0
    }
    BEGIN { US = sprintf("%c", 31); q = ""; lq = ""; n = 0 }
    {
        if (!raw && !cmt && q == "" && !intok && $0 ~ /^[ \t]*(#.*)?\r?$/) next
        line = $0 "\n"
        len = length(line)
        for (i = 1; i <= len; i++) {
            c = substr(line, i, 1)
            if (raw) {
                if (lq != "") {
                    if (lesc) lesc = 0
                    else if (c == "\\") lesc = 1
                    else if (c == lq || c == "\n") lq = ""
                    continue
                }
                if (llong) {
                    if (c == "]" && substr(line, i + 1, 1) == "]") { llong = 0; i++ }
                    continue
                }
                if (lcmt) { if (c == "\n") lcmt = 0; continue }
                if (c == "-" && substr(line, i + 1, 1) == "-") {
                    if (substr(line, i + 2, 2) == "[[") { llong = 1; i += 3 } else lcmt = 1
                    continue
                }
                if (c == "[" && substr(line, i + 1, 1) == "[") { llong = 1; i++; continue }
                if (c == "\"" || c == "\047") { lq = c; continue }
                if (c == "{") rawdepth++
                else if (c == "}") { rawdepth--; if (rawdepth == 0) { raw = 0; print "}\t" } }
                continue
            }
            if (cmt) { if (c == "\n") cmt = 0; continue }
            if (q != "") {
                if (esc) { tok = tok c; esc = 0 }
                else if (c == "\\") esc = 1
                else if (c == q) { q = ""; A[++n] = tok; tok = "" }
                else tok = tok c
                continue
            }
            if (intok) {
                if (esc) { tok = tok c; esc = 0; continue }
                if (c == "\\") { esc = 1; continue }
                if (c == "{" && var) { tok = tok c; var = 0; continue }
                var = (c == "$")
                if (c == " " || c == "\t" || c == "\n" || c == "\r") { A[++n] = tok; tok = ""; intok = 0; continue }
                if (c == ";") { A[++n] = tok; tok = ""; intok = 0; emit(";"); continue }
                if (c == "{") { A[++n] = tok; tok = ""; intok = 0; emit("{"); continue }
                tok = tok c
                continue
            }
            if (c == " " || c == "\t" || c == "\n" || c == "\r") continue
            if (c == "#") { cmt = 1; continue }
            if (c == ";") { if (n > 0) emit(";"); continue }
            if (c == "{") { emit("{"); continue }
            if (c == "}") { n = 0; print "}\t"; continue }
            if (c == "\"" || c == "\047") { q = c; tok = ""; esc = 0; continue }
            intok = 1; tok = ""; esc = 0; var = 0
            if (c == "\\") esc = 1
            else { tok = c; var = (c == "$") }
        }
    }
    END { if (q != "" || raw || intok || n > 0) print "!\t" }' "$1" 2>/dev/null
}

emit_conf() {
    local root=$1 p=$2 cdir=$3 depth=$4 f t incs w n pat prev
    if [ "$depth" -gt 12 ] || [ "$CONF_FILES" -gt 4000 ]; then CONF_PARTIAL=1; return; fi
    if [ -n "$root" ]; then
        p=$(resolve_in "$root" "$p") || { CONF_PARTIAL=1; return; }
    fi
    f="$root$p"
    if [ ! -f "$f" ] || [ ! -r "$f" ]; then
        CONF_PARTIAL=1
        dbg "cannot read $p"
        return
    fi
    CONF_FILES=$((CONF_FILES + 1))
    CONF_SEQ=$((CONF_SEQ + 1))
    t="$TMP/tok.$CONF_SEQ"
    tokenize "$f" > "$t" || CONF_PARTIAL=1
    incs=$(grep -n "^;${TAB}include${SEP}" "$t" 2>/dev/null)
    if [ -z "$incs" ]; then
        cat "$t"
        rm -f "$t"
        return
    fi
    prev=1
    while IFS= read -r w; do
        [ -n "$w" ] || continue
        n=${w%%:*}
        pat=${w#*"$SEP"}
        pat=${pat%%"$SEP"*}
        [ "$n" -gt "$prev" ] && sed -n "${prev},$((n - 1))p" "$t"
        expand_include "$root" "$cdir" "$pat" $((depth + 1))
        prev=$((n + 1))
    done <<EOF
$incs
EOF
    sed -n "${prev},\$p" "$t"
    rm -f "$t"
}

expand_include() {
    local root=$1 cdir=$2 pat=$3 depth=$4 d b m any=0 oldifs
    case "$pat" in /*) ;; *) pat="$cdir/$pat" ;; esac
    d=${pat%/*}
    b=${pat##*/}
    case "$d" in
        *[*?[]*) ;;
        *)
            if [ -n "$root" ]; then
                d=$(resolve_in "$root" "$d") || { CONF_PARTIAL=1; return; }
                [ "$d" = / ] && d=""
            fi ;;
    esac
    oldifs=$IFS
    IFS=
    set +f
    for m in $root$d/$b; do
        set -f
        IFS=$oldifs
        { [ -e "$m" ] || [ -L "$m" ]; } || continue
        any=1
        emit_conf "$root" "${m#"$root"}" "$cdir" "$depth"
    done
    set -f
    IFS=$oldifs
    if [ "$any" -eq 0 ]; then
        case "$d/$b" in *[*?[]*) ;; *) CONF_PARTIAL=1; dbg "include not found: $pat" ;; esac
    fi
}

conf_facts() {
    awk '
    function short(s) {
        if (length(s) > 60) s = substr(s, 1, 57) "..."
        return s
    }
    function setf(k, v) { if (!(k in F)) F[k] = short(v) }
    function arg(i) { return (i <= n) ? A[i] : "" }
    function directive(isblock,    name, rest, i, top) {
        if (n == 0) {
            if (isblock) S[++depth] = "{"
            return
        }
        name = A[1]
        rest = name
        for (i = 2; i <= n; i++) rest = rest " " A[i]
        top = (depth >= 1) ? S[1] : "main"
        if (name == "include") C["unexpanded"]++
        if (top == "http") {
            if (name == "listen") {
                for (i = 2; i <= n; i++) {
                    if (A[i] == "http2") setf("h2", rest)
                    if (A[i] == "quic" || A[i] == "http3") setf("quic", rest)
                }
            } else if (name == "http2") {
                if (depth == 1) { hv = arg(2); hrest = rest }
                else if (depth == 2 && S[2] == "server") { sv[ns] = arg(2); srest[ns] = rest }
            } else if (name ~ /^(proxy|grpc|fastcgi|uwsgi|scgi|memcached)_pass$/) {
                setf("pass", rest)
                if (index(rest, "$")) setf("varpass", rest)
            } else if (name == "resolver") {
                setf("resolver", rest)
            } else if ((name == "mirror" && arg(2) != "off") || (name == "ssi" && arg(2) == "on") ||
                       (name == "auth_request" && arg(2) != "off") ||
                       name == "add_before_body" || name == "add_after_body") {
                setf("subreq", rest)
            } else if (name ~ /_by_lua(_block|_file)?$/ || name ~ /^js_(content|access|header_filter|body_filter|set|periodic)$/) {
                setf("script", name)
            }
            if (isblock && name == "server" && depth == 1) { ns++; sv[ns] = "" }
        } else if (top == "mail") {
            if (isblock && name == "server") C["mailservers"]++
            if (name == "auth_http") setf("authhttp", rest)
        }
        if (isblock) S[++depth] = name
    }
    BEGIN { FS = "\t"; US = sprintf("%c", 31); depth = 0; ns = 0; hv = "" }
    $1 == "!" { C["lexerr"]++; next }
    $1 == "}" { if (depth == 0) C["lexerr"]++; else depth--; next }
    $1 == ";" || $1 == "{" {
        n = split($2, A, US)
        directive($1 == "{")
    }
    END {
        if (depth != 0) C["lexerr"]++
        if (!("h2" in F)) {
            for (s = 1; s <= ns; s++) {
                if (sv[s] == "on") { setf("h2", srest[s]); break }
                if (sv[s] == "" && hv == "on") { setf("h2", hrest " in http{}"); break }
            }
        }
        for (k in F) print k "\t" F[k]
        for (k in C) print k "\t" C[k]
        print "done\t1"
    }'
}

cve() {
    local idx=$1 id=$2 low=$3 lowtxt=$4 cs=$5 ct=$6 st
    if [ "$A_KIND" = upstream ] && [ "$A_KEY" -lt "$low" ]; then
        st=ok; ct="not affected before $lowtxt"
    elif [ "$cs" = ok ]; then
        st=ok
    else
        case " $A_PKGCVES " in
            *" $id "*) st=ok; ct="fix named in the package changelog" ;;
            *)
                if [ "$A_BASE" = unknown ] || [ "$cs" = unknown ]; then st=unknown; else st=impacted; fi ;;
        esac
    fi
    line "$id" "$st" "$ct"
    bump "$idx" "$st"
    case "$st" in
        impacted) R_IMP=1; HITS="$HITS${HITS:+, }$id" ;;
        unknown) R_UNK=1 ;;
    esac
}

print_notes() {
    local l
    [ -n "$1" ] || return 0
    while IFS= read -r l; do
        [ -n "$l" ] && say "  note: $l"
    done <<EOF
$1
EOF
    return 0
}

analyze() {
    local title=$1 bin=$2 root=$3 binpath=$4 popt=$5 copt=$6 notes=$7 replaced=$8
    local vtxt pkgl pkg="" pkgkind="" pmark debug=0 plus="" why
    local pfx conf cdir cfg none k v
    local F_h2="" F_quic="" F_pass="" F_varpass="" F_resolver="" F_subreq="" F_script="" F_authhttp=""
    local F_mail=0 F_unexp=0 F_lexerr=0 F_done=0
    local c1 t1 c2 t2 c3 t3 c4 t4 c5 t5 part=""

    if ! bin_info "$bin"; then
        single "$title" "binary cannot be read, run as root"
        return
    fi
    if [ -z "$B_VERLINE" ]; then
        single "$title" "no nginx version string in this file"
        return
    fi

    case "$B_CONFARGS" in *" --with-debug "*) debug=1 ;; esac
    if [ "$B_MARK_NEW" -eq 1 ] || [ "$B_MARK_OLD" -eq 0 ]; then
        pmark=new
    elif [ -n "$B_CONFARGS" ] && [ "$debug" -eq 0 ]; then
        pmark=old
    else
        pmark=none
    fi

    A_PKGCVES=""
    if [ "$replaced" -eq 0 ]; then
        pkgl=$(pkg_of "$root" "$binpath")
        if [ -n "$pkgl" ]; then
            pkgkind=${pkgl%% *}
            pkg=$(clean "${pkgl#* }")
            A_PKGCVES=$(pkg_cves "$root" "$pkgkind" "${pkg%%=*}")
            [ "$A_PKGCVES" = "-" ] && A_PKGCVES=""
        fi
    fi

    A_KEY=$(ver_key "$B_VERSION")
    case "$(printf '%s' "$B_PRODUCT" | tr 'A-Z' 'a-z')" in
        nginx|openresty) A_KIND=upstream ;;
        *) A_KIND=fork ;;
    esac
    case "$B_BUILD" in *nginx-plus*) plus="; NGINX Plus, see the F5 advisory" ;; esac

    vtxt="$(clean "$B_PRODUCT/$B_VERSION$B_BUILD")"
    [ -n "$B_ALT" ] && vtxt="$vtxt [$(clean "$B_ALT")]"
    [ -n "$pkg" ] && vtxt="$vtxt, package $pkg"

    if [ "$A_KIND" = upstream ] && is_fixed "$A_KEY"; then
        A_BASE=ok; why="has the fixes"
    elif [ "$A_KIND" = upstream ] && [ "$A_KEY" -lt "$LOW5" ]; then
        A_BASE=ok; why="older than every affected release"
    elif pkg_fixed "$pkgkind" "$pkg"; then
        A_BASE=ok; why="package listed as fixed"
    elif [ "$A_KIND" = fork ]; then
        A_BASE=unknown; why="fork with its own version numbers, check the vendor advisory"
    elif [ "$pmark" = new ]; then
        A_BASE=unknown
        why="affected range, but the binary carries the resolver fix, so probably a backport: confirm with the vendor advisory$plus"
    elif [ "$pmark" = old ]; then
        A_BASE=impacted; why="affected range, unpatched resolver code in the binary$plus"
    elif [ "$debug" -eq 1 ]; then
        A_BASE=impacted; why="affected range; a backport cannot be seen in a debug build$plus"
    else
        A_BASE=impacted; why="affected range; build options unreadable, so a backport cannot be looked for$plus"
    fi
    [ -n "$A_PKGCVES" ] && why="$why; package changelog names $A_PKGCVES"

    say ""
    say "$title"
    say "  version: $vtxt: $why"

    if [ "$A_BASE" = ok ]; then
        line "$ID1" ok "$why"
        line "$ID2" ok "$why"
        line "$ID3" ok "$why"
        line "$ID4" ok "$why"
        line "$ID5" ok "$why"
        print_notes "$notes"
        result_line ok
        tally ok
        return
    fi

    pfx=$(conf_arg prefix)
    conf=$(conf_arg conf-path)
    [ -n "$pfx" ] || pfx=/usr/local/nginx
    [ -n "$conf" ] || conf=conf/nginx.conf
    [ -n "$popt" ] && pfx=$popt
    [ -n "$copt" ] && conf=$copt
    case "$conf" in /*) ;; *) conf="${pfx%/}/$conf" ;; esac
    if [ -z "$copt" ] && [ -z "$B_CONFARGS" ] && [ ! -e "$root$conf" ]; then
        for k in /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf; do
            [ -e "$root$k" ] && { conf=$k; break; }
        done
    fi
    cdir=${conf%/*}
    CONF_PARTIAL=0
    CONF_FILES=0
    emit_conf "$root" "$conf" "$cdir" 0 > "$TMP/conf"
    cfg=ok
    if [ "$CONF_FILES" -eq 0 ]; then
        cfg=unreadable
    else
        conf_facts < "$TMP/conf" > "$TMP/facts" 2>/dev/null
        while IFS="$TAB" read -r k v; do
            case "$k" in
                h2) F_h2=$v ;;
                quic) F_quic=$v ;;
                pass) F_pass=$v ;;
                varpass) F_varpass=$v ;;
                resolver) F_resolver=$v ;;
                subreq) F_subreq=$v ;;
                script) F_script=$v ;;
                authhttp) F_authhttp=$v ;;
                mailservers) F_mail=$v ;;
                unexpanded) F_unexp=$v ;;
                lexerr) F_lexerr=$v ;;
                done) F_done=$v ;;
            esac
        done < "$TMP/facts"
        if [ "$CONF_PARTIAL" -eq 1 ] || [ "$F_unexp" != 0 ] || [ "$F_lexerr" != 0 ] || [ "$F_done" != 1 ]; then cfg=partial; fi
    fi
    dbg "$title: conf=$conf files=$CONF_FILES cfg=$cfg h2=[$F_h2] quic=[$F_quic] pass=[$F_pass] varpass=[$F_varpass] resolver=[$F_resolver] subreq=[$F_subreq] script=[$F_script] mail=$F_mail"

    none=ok
    if [ "$cfg" = partial ]; then none=unknown; part=", but the configuration was only partly read"; fi
    conf=$(clean "$conf")

    if ! built ' --with-http_v2_module '; then c1=ok; t1="http_v2 module not built"
    elif [ "$cfg" = unreadable ]; then c1=unknown; t1="cannot read $conf"
    elif [ -n "$F_h2" ]; then c1=impacted; t1="http/2 enabled: $F_h2"
    else c1=$none; t1="http/2 not enabled$part"
    fi

    if ! built ' --with-http_v2_module '; then c2=ok; t2="http_v2 module not built"
    elif [ "$cfg" = unreadable ]; then c2=unknown; t2="cannot read $conf"
    elif [ -z "$F_h2" ]; then c2=$none; t2="http/2 not enabled$part"
    elif [ -n "$F_pass" ]; then c2=impacted; t2="http/2 with $F_pass"
    elif [ -n "$F_script" ]; then c2=unknown; t2="http/2 on, no *_pass, but $F_script may open connections"
    else c2=$none; t2="http/2 on, nothing passed upstream$part"
    fi

    if ! built ' --with-http_v3_module '; then c3=ok; t3="http_v3 module not built"
    elif [ "$cfg" = unreadable ]; then c3=unknown; t3="cannot read $conf"
    elif [ -z "$F_quic" ]; then c3=$none; t3="no quic listener$part"
    elif [ -n "$F_pass" ]; then c3=impacted; t3="$F_quic, with $F_pass"
    elif [ -n "$F_script" ]; then c3=unknown; t3="$F_quic, no *_pass, but $F_script may open connections"
    else c3=$none; t3="quic on, nothing passed upstream$part"
    fi

    if [ "$cfg" = unreadable ]; then c4=unknown; t4="cannot read $conf"
    elif [ -z "$F_resolver" ]; then c4=$none; t4="no resolver in http{}$part"
    elif [ -z "$F_varpass" ]; then c4=$none; t4="resolver set, no *_pass with a variable$part"
    elif [ -n "$F_subreq" ]; then c4=impacted; t4="$F_resolver, $F_varpass, $F_subreq"
    else c4=unknown; t4="resolver and $F_varpass; no mirror/ssi/auth_request seen, other subrequest sources not ruled out"
    fi

    if ! built ' --with-mail(=dynamic)? '; then c5=ok; t5="mail module not built"
    elif [ "$cfg" = unreadable ]; then c5=unknown; t5="cannot read $conf"
    elif [ "$F_mail" != 0 ]; then
        c5=impacted; t5="mail{} with $F_mail server(s)"
        [ -n "$F_authhttp" ] && t5="$t5, $F_authhttp"
    else c5=$none; t5="no mail{} servers$part"
    fi

    HITS=""
    R_IMP=0
    R_UNK=0
    cve 1 "$ID1" "$LOW1" 1.9.5 "$c1" "$t1"
    cve 2 "$ID2" "$LOW2" 1.19.7 "$c2" "$t2"
    cve 3 "$ID3" "$LOW3" 1.25.0 "$c3" "$t3"
    cve 4 "$ID4" "$LOW4" 0.6.18 "$c4" "$t4"
    cve 5 "$ID5" "$LOW5" 0.5.33 "$c5" "$t5"

    [ "$cfg" = partial ] && notes="${notes:+$notes$NL}part of the configuration could not be read or parsed; run as root, or check it by hand"
    print_notes "$notes"

    if [ "$R_IMP" -eq 1 ]; then
        result_line impacted "$HITS"; tally impacted
    elif [ "$R_UNK" -eq 1 ]; then
        result_line unknown; tally unknown
    else
        result_line ok; tally ok
    fi
}

resolve() {
    readlink -f "$1" 2>/dev/null || realpath "$1" 2>/dev/null || printf '%s\n' "$1"
}

add_cand() {
    local r
    { [ -f "$1" ] && [ -x "$1" ]; } || return 0
    r=$(resolve "$1")
    grep -qxF -- "$r" "$TMP/cands" || printf '%s\n' "$r" >> "$TMP/cands"
}

discover_disk() {
    local n p
    for n in nginx openresty angie tengine freenginx; do
        p=$(command -v "$n" 2>/dev/null) || p=""
        [ -n "$p" ] && add_cand "$p"
    done
    set +f
    for p in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx \
             /usr/local/openresty/nginx/sbin/nginx /usr/local/openresty/bin/openresty \
             /usr/sbin/angie /usr/local/angie/sbin/angie \
             /usr/sbin/tengine /usr/local/tengine/sbin/nginx \
             /opt/zimbra/common/sbin/nginx \
             /opt/*/sbin/nginx /opt/*/nginx/sbin/nginx /opt/*/*/sbin/nginx \
             /usr/local/*/sbin/nginx /usr/local/*/nginx/sbin/nginx; do
        add_cand "$p"
    done
    set -f
}

proc_line() {
    printf '%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n' "$1" "$SEP" "$2" "$SEP" "$3" "$SEP" "$4" "$SEP" \
        "$5" "$SEP" "$6" "$SEP" "$7" "$SEP" "$8" >> "$TMP/procs"
}

scan_procs_linux() {
    local d pid cmd exe args tok prev popt copt root ns self_ns init_ns rootlink binpath tag note st cwd where hn replaced
    self_ns=$(readlink /proc/self/ns/mnt 2>/dev/null) || self_ns=""
    init_ns=$(readlink /proc/1/ns/mnt 2>/dev/null) || init_ns=""
    set +f
    for d in /proc/[0-9]*; do
        set -f
        pid=${d#/proc/}
        [ "$pid" = "$$" ] && continue
        [ -r "$d/cmdline" ] || continue
        cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null) || continue
        [ -n "$cmd" ] || continue
        exe=$(readlink "$d/exe" 2>/dev/null) || exe=""
        case "$cmd" in
            "nginx: master process "*|"angie: master process "*|"tengine: master process "*)
                args=${cmd#*: master process } ;;
            *": worker process is shutting down"*)
                st=$(cat "$d/stat" 2>/dev/null) || st=""
                st=${st##*) }
                set -- $st
                [ $# -ge 2 ] && printf '%s\n' "$2" >> "$TMP/draining"
                continue ;;
            *)
                case "${exe% (deleted)}" in
                    */nginx|*/nginx-debug|*/openresty|*/angie|*/tengine|*/freenginx) ;;
                    *) continue ;;
                esac
                case "$cmd" in *": "*" process"*) continue ;; esac
                case " $cmd " in *" -t "*|*" -T "*|*" -s "*|*" -v "*|*" -V "*|*" -h "*|*" -? "*) continue ;; esac
                args=$cmd ;;
        esac

        popt=""; copt=""; prev=""; tag=""
        for tok in $args; do
            [ -n "$tag" ] || tag=$tok
            case "$prev" in
                -c) copt=$tok ;;
                -p) popt=$tok ;;
            esac
            prev=$tok
        done
        tag=$(clean "$tag")

        if [ -z "$exe" ] || [ ! -r "$d/exe" ]; then
            single "$tag (pid $pid)" "cannot read /proc/$pid/exe, run as root"
            continue
        fi
        binpath=${exe% (deleted)}

        root=""
        note=""
        where=""
        replaced=0
        ns=$(readlink "$d/ns/mnt" 2>/dev/null) || ns=""
        rootlink=$(readlink "$d/root" 2>/dev/null) || rootlink=/
        if [ -n "$ns" ] && [ -n "$self_ns" ] && [ "$ns" != "$self_ns" ]; then
            root="$d/root"
            if [ "$ns" = "$init_ns" ]; then
                where=", host"
            else
                hn=""
                if [ -r "$root/etc/hostname" ]; then IFS= read -r hn < "$root/etc/hostname" || true; fi
                hn=$(printf '%s' "$hn" | tr -cd 'A-Za-z0-9._-' | cut -c1-80)
                where=", container${hn:+ $hn}"
            fi
        elif [ "$rootlink" != / ]; then
            root="$d/root"
            where=", chroot"
        elif [ "$exe" = "$binpath" ]; then
            printf '%s\n' "$binpath" >> "$TMP/running"
        fi
        tag="$binpath (pid $pid$where)"
        if [ -n "$root" ] && [ ! -d "$root/" ]; then
            single "$(clean "$tag")" "cannot read /proc/$pid/root, run as root"
            continue
        fi
        case "$popt" in
            ""|/*) ;;
            *) cwd=$(readlink "$d/cwd" 2>/dev/null) || cwd=""
               popt="$cwd/$popt" ;;
        esac
        if [ "$exe" != "$binpath" ]; then
            replaced=1
            note="the binary was replaced on disk after this nginx started; the result is for the running copy. Restart nginx (a reload is not enough) to run the new one"
        fi
        proc_line "$pid" "$root" "$(clean "$tag")" "$binpath" "$popt" "$copt" "$replaced" "$note"
    done
    set -f
}

kernel_sctp() {
    local kroot="" rel a b txt f found=""
    [ "$(uname -s)" = Linux ] || return 0
    a=$(readlink /proc/1/ns/mnt 2>/dev/null) || a=""
    b=$(readlink /proc/self/ns/mnt 2>/dev/null) || b=""
    if [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ] && [ -d /proc/1/root/etc ]; then
        kroot=/proc/1/root
    fi
    rel=$(uname -r)
    set +f
    for f in "$kroot"/etc/modprobe.d/*.conf "$kroot"/run/modprobe.d/*.conf \
             "$kroot"/usr/lib/modprobe.d/*.conf "$kroot"/lib/modprobe.d/*.conf; do
        [ -r "$f" ] || continue
        if grep -qE '^[[:space:]]*install[[:space:]]+sctp[[:space:]]+(/usr)?/bin/(false|true)' "$f" 2>/dev/null; then
            found=${f#"$kroot"}
            break
        fi
    done
    set -f
    if grep -q '^sctp ' /proc/modules 2>/dev/null; then
        txt="reachable: the sctp module is loaded"
        [ -n "$found" ] && txt="$txt ($found blocks loading, but does not unload it)"
    elif [ -d /sys/module/sctp ]; then
        txt="reachable: sctp is built into this kernel"
    elif [ -n "$found" ]; then
        txt="blocked: sctp is not loaded and $found stops it loading"
    else
        set +f
        set -- "$kroot"/lib/modules/"$rel"/kernel/net/sctp/sctp.ko*
        set -f
        if [ -e "$1" ]; then
            txt="reachable: sctp is not loaded but loads on demand (no \"install sctp /bin/false\" in modprobe.d)"
        elif [ -d "$kroot/lib/modules/$rel" ]; then
            txt="not present: no sctp module for this kernel"
        else
            txt="unknown: sctp is not loaded, and this kernel's modules cannot be seen from here"
        fi
    fi
    say ""
    say "host kernel $rel (the separate, unpatched root step; not part of the verdict)"
    say "  sctp: $txt"
}

HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)
IS_ROOT=0
[ "$(id -u)" = 0 ] && IS_ROOT=1

header
say "host: $HOST_OS $HOST_ARCH"

[ "$SCAN_DISK" -eq 1 ] && discover_disk
while IFS= read -r b; do
    [ -n "$b" ] || continue
    if [ -n "$ROOT_OPT" ]; then
        r=$(resolve_in "$ROOT_OPT" "$b") || r=""
        if [ -n "$r" ] && [ -f "$ROOT_OPT$r" ]; then
            printf 'extra:%s\n' "$r" >> "$TMP/cands"
        else
            printf 'missing:%s\n' "$b" >> "$TMP/cands"
        fi
    elif [ -f "$b" ]; then
        r=$(resolve "$b")
        grep -qxF -- "$r" "$TMP/cands" || printf 'extra:%s\n' "$r" >> "$TMP/cands"
    else
        printf 'missing:%s\n' "$b" >> "$TMP/cands"
    fi
done <<EOF
$EXTRA_BINS
EOF

if [ "$SCAN_PROCS" -eq 1 ]; then
    case "$HOST_OS" in
        Linux) scan_procs_linux ;;
        *) say "note: process scan not supported on $HOST_OS" ;;
    esac
    [ "$IS_ROOT" -eq 1 ] || say "note: not root; other users' nginx processes and containers may be missed"
fi

while IFS="$SEP" read -r pid root tag binpath popt copt replaced note; do
    [ -n "$pid" ] || continue
    drain=$(grep -cxF -- "$pid" "$TMP/draining" 2>/dev/null) || drain=0
    if [ "$drain" -gt 0 ]; then
        note="${note:+$note$NL}$drain old worker(s) still shutting down; they keep the previous configuration until they exit"
    fi
    analyze "$tag" "/proc/$pid/exe" "$root" "$binpath" "$popt" "$copt" "$note" "$replaced"
done < "$TMP/procs"

while IFS= read -r b; do
    [ -n "$b" ] || continue
    case "$b" in
        missing:*) single "${b#missing:} (-b)" "not a file"; continue ;;
        extra:*)
            b=${b#extra:}
            if [ -n "$ROOT_OPT" ]; then
                analyze "$b (-b, root $ROOT_OPT)" "$ROOT_OPT$b" "$ROOT_OPT" "$b" "" "$CONF_OPT" "" 0
                continue
            fi
            t="$b (-b)" ;;
        *)
            grep -qxF -- "$b" "$TMP/running" && continue
            bin_info "$b" || continue
            [ -n "$B_VERLINE" ] || continue
            t="$b (installed, not running)" ;;
    esac
    analyze "$t" "$b" "" "$b" "" "$CONF_OPT" "" 0
done < "$TMP/cands"

[ "$SCAN_KERNEL" -eq 1 ] && kernel_sctp

finish
