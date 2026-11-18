#!/usr/bin/env bash
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
S="$HERE/../detect-nginx2root.sh"
REAL_VULN=""
REAL_FIXED=""
IMAGE=""
SCAN_IMAGE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --detector) S=$2; shift ;;
        --real-vulnerable) REAL_VULN=$2; shift ;;
        --real-fixed) REAL_FIXED=$2; shift ;;
        --container-image) IMAGE=$2; shift ;;
        --scan-image) SCAN_IMAGE=$2; shift ;;
        *) echo "unknown argument: $1" >&2; exit 3 ;;
    esac
    shift
done
[ -n "$SCAN_IMAGE" ] || SCAN_IMAGE=$IMAGE

PASS=0
FAIL=0
WORK=$(mktemp -d)
PIDS=""
CONTAINERS=""

cleanup() {
    local p
    for p in $PIDS; do
        pkill -9 -P "$p" 2>/dev/null
        kill -9 "$p" 2>/dev/null
    done
    for p in $CONTAINERS; do docker rm -f "$p" >/dev/null 2>&1; done
    rm -rf "$WORK"
}
trap cleanup EXIT

verdict() {
    case "$1" in
        0) echo "not impacted" ;;
        1) echo "impacted" ;;
        2) echo "unknown" ;;
        *) echo "" ;;
    esac
}

run() {
    OUT=$("$@" 2>&1)
    CODE=$?
    LAST=$(printf '%s\n' "$OUT" | sed '/^[[:space:]]*$/d' | tail -1)
}

has() {
    local c
    for c in "$@"; do
        case "$c" in
            =*) printf '%s\n' "$OUT" | grep -qxF -- "${c#=}" || return 1 ;;
            !*) printf '%s\n' "$OUT" | grep -qF -- "${c#!}" && return 1 ;;
            *) printf '%s\n' "$OUT" | grep -qF -- "$c" || return 1 ;;
        esac
    done
    return 0
}

report() {
    if [ "$1" -eq 1 ]; then
        PASS=$((PASS + 1))
        echo "PASS  $2"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL  $2 ($3)"
        printf '%s\n' "$OUT" | sed 's/^/      | /'
    fi
}

check() {
    local name=$1 want=$2 ok=1 n
    shift 2
    [ "$CODE" = "$want" ] || ok=0
    if [ "$want" != 3 ]; then
        [ "$LAST" = "$(verdict "$want")" ] || ok=0
        n=$(printf '%s\n' "$OUT" | grep -cE '^CVE-2026-[0-9]+: (impacted|not impacted|unknown)$')
        [ "$n" = 5 ] || ok=0
    fi
    has "$@" || ok=0
    if printf '%s\n' "$OUT" | grep -qE 'Broken pipe|write error|syntax error|unbound variable'; then ok=0; fi
    report "$ok" "$name" "want exit $want '$(verdict "$want")' with [$*]; got exit $CODE"
}

block() {
    OUT=$(printf '%s\n' "$OUT" | awk -v p="(pid $1" 'index($0, p) { f = 1 } f && /^$/ { exit } f')
}

check_block() {
    local name=$1 ok=1
    shift
    [ -n "$OUT" ] || ok=0
    has "$@" || ok=0
    report "$ok" "$name" "want a block with [$*]"
}

ALL="--prefix=/usr/local/nginx --conf-path=/etc/nginx/nginx.conf --with-http_ssl_module --with-http_v2_module --with-http_v3_module --with-mail --with-mail_ssl_module --with-stream"

mkbin() {
    local f=$1 ver=$2 args=$3 m
    shift 3
    {
        printf '\177ELF\0\0junk\0'
        printf '%s\n\0' "$ver"
        [ "$args" = none ] || printf 'configure arguments: %s\n\0' "$args"
        for m in "$@"; do
            case "$m" in
                old) printf 'could not cancel %%V resolving\0' ;;
                new) printf 'mail auth http block write\0' ;;
            esac
        done
        printf 'tail\0'
    } > "$f"
    chmod 755 "$f"
}

det() {
    local b=$1 c=$2
    shift 2
    run bash "$S" --no-procs --no-disk --no-kernel -b "$b" -c "$c" "$@"
}

echo "bash: $BASH_VERSION"
echo "detector: $S"

B="$WORK/bin"
C="$WORK/conf"
mkdir -p "$B" "$C"

cat > "$C/h2.conf" <<'EOF'
events {}
http {
    server {
        listen 443 ssl http2;
        location / { proxy_pass http://127.0.0.1:9000; }
    }
}
EOF
cat > "$C/static.conf" <<'EOF'
events {}
http { server { listen 80; root /srv; } }
EOF
cat > "$C/quic.conf" <<'EOF'
events {}
http {
    server {
        listen 443 quic reuseport;
        listen 443 ssl;
        location / { proxy_pass http://127.0.0.1:9000; }
    }
}
EOF

echo "## 1. version logic"

mkbin "$B/v1318" "nginx version: nginx/1.31.8" "$ALL" old
det "$B/v1318" "$C/h2.conf"
check "1.31.8 with http/2 and proxy_pass is impacted" 1 \
    "=CVE-2026-123007: impacted" "=CVE-2026-123633: impacted" "=CVE-2026-121810: not impacted" \
    "=CVE-2026-123634: not impacted" "=CVE-2026-113425: not impacted" \
    "unpatched resolver code in the binary" " => impacted (CVE-2026-123007, CVE-2026-123633)"

mkbin "$B/v1319" "nginx version: nginx/1.31.9" "$ALL"
det "$B/v1319" "$C/h2.conf"
check "1.31.9 is fixed" 0 "has the fixes" "=CVE-2026-123007: not impacted" "!impacted (CVE"

mkbin "$B/v1307" "nginx version: nginx/1.30.7" "$ALL"
det "$B/v1307" "$C/h2.conf"
check "1.30.7 is fixed" 0 "has the fixes"

mkbin "$B/v13012" "nginx version: nginx/1.30.12" "$ALL"
det "$B/v13012" "$C/h2.conf"
check "1.30.12 is fixed" 0 "has the fixes"

mkbin "$B/v1306" "nginx version: nginx/1.30.6" "$ALL" old
det "$B/v1306" "$C/h2.conf"
check "1.30.6 is impacted" 1 "=CVE-2026-123007: impacted"

mkbin "$B/v1320" "nginx version: nginx/1.32.0" "$ALL"
det "$B/v1320" "$C/h2.conf"
check "1.32.0, a later branch, is fixed" 0 "has the fixes"

mkbin "$B/v194" "nginx version: nginx/1.9.4" "$ALL" old
det "$B/v194" "$C/h2.conf"
check "1.9.4 predates both http/2 bugs" 0 "CVE-2026-123007: not impacted (not affected before 1.9.5)" \
    "CVE-2026-123633: not impacted (not affected before 1.19.7)"

mkbin "$B/v1196" "nginx version: nginx/1.19.6" "$ALL" old
det "$B/v1196" "$C/h2.conf"
check "1.19.6 has the window bug but not the http/2 use-after-free" 1 \
    "=CVE-2026-123007: impacted" "=CVE-2026-123633: not impacted" "not affected before 1.19.7"

mkbin "$B/v1249" "nginx version: nginx/1.24.9" "$ALL" old
det "$B/v1249" "$C/quic.conf"
check "1.24.9 predates the http/3 bug" 0 "CVE-2026-121810: not impacted (not affected before 1.25.0)"

mkbin "$B/v1250" "nginx version: nginx/1.25.0" "$ALL" old
det "$B/v1250" "$C/quic.conf"
check "1.25.0 with quic and proxy_pass is impacted" 1 "=CVE-2026-121810: impacted" "=CVE-2026-123007: not impacted"

mkbin "$B/v0530" "nginx version: nginx/0.5.30" none old
det "$B/v0530" "$C/h2.conf"
check "0.5.30 is older than every affected release" 0 "older than every affected release"

mkbin "$B/backport" "nginx version: nginx/1.26.2" "$ALL"
det "$B/backport" "$C/h2.conf"
check "affected version without the unpatched string is unknown" 2 \
    "probably a backport" "=CVE-2026-123007: unknown" "=CVE-2026-121810: not impacted"

mkbin "$B/debug" "nginx version: nginx/1.24.0 (Ubuntu)" "$ALL --with-debug" old
det "$B/debug" "$C/h2.conf"
check "debug build in the affected range is impacted" 1 "nginx/1.24.0 (Ubuntu)" \
    "a backport cannot be seen in a debug build" "=CVE-2026-123007: impacted"

mkbin "$B/debugfixed" "nginx version: nginx/1.24.0 (Ubuntu)" "$ALL --with-debug" old new
det "$B/debugfixed" "$C/h2.conf"
check "debug build with a patched-only string is unknown" 2 "probably a backport"

mkbin "$B/noargs" "nginx version: nginx/1.24.0" none old
det "$B/noargs" "$C/h2.conf"
check "unreadable build options stay impacted" 1 "build options unreadable"

mkbin "$B/openresty" "nginx version: openresty/1.27.1.2" "$ALL" old
det "$B/openresty" "$C/h2.conf"
check "openresty is judged on its nginx core" 1 "openresty/1.27.1.2" "=CVE-2026-123007: impacted"

mkbin "$B/openrestyfixed" "nginx version: openresty/1.31.9.1" "$ALL"
det "$B/openrestyfixed" "$C/h2.conf"
check "openresty on a fixed core" 0 "has the fixes"

mkbin "$B/angie" "Angie version: Angie/1.8.0" "$ALL" old
det "$B/angie" "$C/h2.conf"
check "a fork with its own numbering is unknown" 2 "Angie/1.8.0" "fork with its own version numbers" \
    "=CVE-2026-123007: unknown"
det "$B/angie" "$C/static.conf"
check "a fork with nothing enabled is not impacted" 0 "=CVE-2026-123007: not impacted"

{
    printf '\177ELF\0'
    printf 'Tengine version: Tengine/3.1.0\n\0nginx version: nginx/1.24.0\n\0'
    printf 'configure arguments: %s\n\0could not cancel %%V resolving\0' "$ALL"
} > "$B/tengine"
det "$B/tengine" "$C/h2.conf"
check "tengine is judged on the nginx version it reports" 1 "nginx/1.24.0 [Tengine/3.1.0]"

mkbin "$B/plus" "nginx version: nginx/1.29.3 (nginx-plus-r36)" "$ALL" old
det "$B/plus" "$C/h2.conf"
check "NGINX Plus points at the F5 advisory" 1 "NGINX Plus, see the F5 advisory"

printf 'not nginx at all\n' > "$B/other"
det "$B/other" "$C/h2.conf"
check "a file without a version string is unknown" 2 "no nginx version string" "=CVE-2026-113425: unknown"

det "$B/does-not-exist" "$C/h2.conf"
check "a missing -b file is unknown" 2 "not a file"

run bash "$S" --bogus
check "bad argument" 3
run bash "$S" -b
check "missing option value" 3
run bash "$S" -r "$WORK/no-such-dir" -b /x
check "missing --root directory" 3

run env NGINX2ROOT_FIXED_IN="1.24.1" bash "$S" --no-procs --no-disk --no-kernel -b "$B/debug" -c "$C/h2.conf"
check "NGINX2ROOT_FIXED_IN below the version" 1
mkbin "$B/v1245" "nginx version: nginx/1.24.5" "$ALL" old
run env NGINX2ROOT_FIXED_IN="1.24.1" bash "$S" --no-procs --no-disk --no-kernel -b "$B/v1245" -c "$C/h2.conf"
check "NGINX2ROOT_FIXED_IN at or above the entry" 0 "has the fixes"

det "$B/v1318" "$C/h2.conf" -q
n=$(printf '%s\n' "$OUT" | wc -l)
ok=1; [ "$n" -eq 6 ] || ok=0
[ "$CODE" = 1 ] && [ "$LAST" = impacted ] || ok=0
has "=CVE-2026-123007: impacted" "=CVE-2026-113425: not impacted" || ok=0
report "$ok" "-q prints the five status lines and the verdict" "got $n lines, exit $CODE"

det "$B/v1318" "$C/h2.conf" -b "$B/v1319"
check "two binaries: the worst state wins" 1 "=CVE-2026-123007: impacted"
n=$(printf '%s\n' "$OUT" | grep -c '^  => ')
report "$([ "$n" -eq 2 ] && echo 1 || echo 0)" "two binaries give two blocks" "got $n"

echo "## 2. configuration logic"
V="$B/v1318"

det "$V" "$C/static.conf"
check "plain site is not impacted" 0 "http/2 not enabled" "no quic listener" "no resolver in http{}" "no mail{} servers"

cat > "$C/h2on.conf" <<'EOF'
events {}
http { server { listen 443 ssl; http2 on; } }
EOF
det "$V" "$C/h2on.conf"
check "http2 on in a server" 1 "CVE-2026-123007: impacted (http/2 enabled: http2 on)" \
    "=CVE-2026-123633: not impacted" "nothing passed upstream"

cat > "$C/h2inherit.conf" <<'EOF'
events {}
http {
    http2 on;
    server { listen 443 ssl; }
}
EOF
det "$V" "$C/h2inherit.conf"
check "http2 on inherited from http{}" 1 "http2 on in http{}"

cat > "$C/h2alloff.conf" <<'EOF'
events {}
http {
    http2 on;
    server { listen 443 ssl; http2 off; }
    server { listen 8443 ssl; http2 off; }
}
EOF
det "$V" "$C/h2alloff.conf"
check "http2 on in http{} but off in every server" 0 "http/2 not enabled"

cat > "$C/h2oneoff.conf" <<'EOF'
events {}
http {
    http2 on;
    server { listen 443 ssl; http2 off; }
    server { listen 8443 ssl; }
}
EOF
det "$V" "$C/h2oneoff.conf"
check "http2 on in http{}, off in one server only" 1 "=CVE-2026-123007: impacted"

cat > "$C/h2noservers.conf" <<'EOF'
events {}
http { http2 on; }
EOF
det "$V" "$C/h2noservers.conf"
check "http2 on with no server" 0

for p in grpc_pass fastcgi_pass uwsgi_pass scgi_pass memcached_pass; do
    cat > "$C/pass.conf" <<EOF
events {}
http { server { listen 443 ssl http2; location / { $p backend:9000; } } }
EOF
    det "$V" "$C/pass.conf"
    check "http/2 with $p" 1 "CVE-2026-123633: impacted (http/2 with $p backend:9000)"
done

cat > "$C/quicstatic.conf" <<'EOF'
events {}
http { server { listen 443 quic; listen 443 ssl; root /srv; } }
EOF
det "$V" "$C/quicstatic.conf"
check "quic with nothing passed upstream" 0 "quic on, nothing passed upstream"

mkbin "$B/noh2" "nginx version: nginx/1.31.8" "--prefix=/usr/local/nginx --with-http_ssl_module --with-mail" old
det "$B/noh2" "$C/h2.conf"
check "http_v2 module not built" 0 "http_v2 module not built" "http_v3 module not built"

cat > "$C/resolver.conf" <<'EOF'
events {}
http {
    resolver 10.0.0.2 valid=30s;
    server {
        listen 80;
        location / { mirror /mirror; proxy_pass http://$host; }
        location = /mirror { internal; proxy_pass http://$host$request_uri; }
    }
}
EOF
det "$V" "$C/resolver.conf"
check "resolver, variable proxy_pass and mirror" 1 "=CVE-2026-123634: impacted" \
    'resolver 10.0.0.2 valid=30s, proxy_pass http://$host, mirror /mirror' "=CVE-2026-123007: not impacted"

cat > "$C/resolvernosub.conf" <<'EOF'
events {}
http {
    resolver 10.0.0.2;
    server { listen 80; location / { mirror off; proxy_pass http://$host; } }
}
EOF
det "$V" "$C/resolvernosub.conf"
check "resolver and variable proxy_pass without a subrequest directive" 2 \
    "=CVE-2026-123634: unknown" "other subrequest sources not ruled out"

cat > "$C/resolverfixed.conf" <<'EOF'
events {}
http {
    resolver 10.0.0.2;
    server { listen 80; location / { mirror /m; proxy_pass http://backend; } }
}
EOF
det "$V" "$C/resolverfixed.conf"
check "resolver with a fixed proxy_pass" 0 "resolver set, no *_pass with a variable"

for d in "ssi on" "auth_request /auth" "add_before_body /hdr" "add_after_body /ftr"; do
    cat > "$C/sub.conf" <<EOF
events {}
http {
    resolver 10.0.0.2;
    server { listen 80; location / { $d; proxy_pass http://\$host; } }
}
EOF
    det "$V" "$C/sub.conf"
    check "resolver with $d" 1 "=CVE-2026-123634: impacted"
done

cat > "$C/mail.conf" <<'EOF'
events {}
mail {
    auth_http 127.0.0.1:9000/auth;
    server { listen 143; protocol imap; }
    server { listen 25; protocol smtp; }
}
http { server { listen 80; } }
EOF
det "$V" "$C/mail.conf"
check "mail proxy" 1 "=CVE-2026-113425: impacted" "mail{} with 2 server(s), auth_http 127.0.0.1:9000/auth" \
    "=CVE-2026-123007: not impacted"

mkbin "$B/nomail" "nginx version: nginx/1.31.8" "--prefix=/usr/local/nginx --with-http_v2_module" old
det "$B/nomail" "$C/mail.conf"
check "mail module not built" 0 "mail module not built"

mkbin "$B/dynmail" "nginx version: nginx/1.31.8" "--prefix=/usr/local/nginx --with-mail=dynamic --with-http_v2_module" old
det "$B/dynmail" "$C/mail.conf"
check "mail built as a dynamic module" 1 "=CVE-2026-113425: impacted"

cat > "$C/mailempty.conf" <<'EOF'
events {}
mail { auth_http 127.0.0.1:9000/auth; }
EOF
det "$V" "$C/mailempty.conf"
check "mail{} without a server" 0 "no mail{} servers"

cat > "$C/stream.conf" <<'EOF'
events {}
stream {
    server { listen 8443 http2; proxy_pass 10.0.0.5:443; }
}
http { server { listen 443 ssl http2; root /srv; } }
EOF
det "$V" "$C/stream.conf"
check "stream{} directives are not http ones" 1 "=CVE-2026-123007: impacted" "=CVE-2026-123633: not impacted"

cat > "$C/comments.conf" <<'EOF'
events {}
http {
    # listen 443 ssl http2;
    server {
        listen 80;   # http2 on;
        location /a { return 200 "listen 443 ssl http2; http2 on; proxy_pass x;"; }
        location /b { set $x 'http2 on; } mail { server {'; }
        #http2 on;
    }
}
# mail { server { listen 25; } }
EOF
det "$V" "$C/comments.conf"
check "comments and quoted strings are not directives" 0 "http/2 not enabled" "no mail{} servers"

cat > "$C/escapes.conf" <<'EOF'
events {}
http {
    map $uri $x { "~^/a{2}" 1; default 0; }
    server {
        listen 80;
        location ~ \.php$ { return 200 "a\"b; listen 443 http2;"; }
        location ~* "^/x{1,3}/" { proxy_set_header X-A "v;{}#"; }
        location /v { proxy_set_header Host ${host}; }
    }
    server { listen 443 ssl http2; }
}
EOF
det "$V" "$C/escapes.conf"
check "regexes, escapes and \${var} do not derail the tokenizer" 1 "listen 443 ssl http2" "!partly read"

cat > "$C/lua.conf" <<'EOF'
events {}
http {
    server {
        listen 80;
        location /lua {
            content_by_lua_block {
                -- a comment with a brace } and a quote "
                local t = { a = "}", b = '{' }
                local n = #t
                local s = [[ listen 443 ssl http2; } ]]
                --[[ long comment
                     http2 on; } ]]
                ngx.say("mail { server { listen 25; } }")
            }
        }
    }
    server { listen 8443 ssl http2; }
}
EOF
det "$V" "$C/lua.conf"
check "Lua block bodies are skipped, directives after them are read" 1 \
    "http/2 enabled: listen 8443 ssl http2" "=CVE-2026-113425: not impacted" "!partly read" \
    "=CVE-2026-123633: unknown" "content_by_lua_block may open connections"

cat > "$C/luaonly.conf" <<'EOF'
events {}
http {
    server {
        listen 80;
        location / { content_by_lua_block { ngx.say("listen 443 ssl http2;") } }
    }
}
EOF
det "$V" "$C/luaonly.conf"
check "text inside Lua does not enable anything" 0 "http/2 not enabled"

mkdir -p "$C/inc/conf.d" "$C/inc/sites" "$C/inc/snippets"
cat > "$C/inc/nginx.conf" <<'EOF'
events {}
http {
    include mime.types;
    include conf.d/*.conf;
    include "sites/site one.conf";
}
EOF
printf 'types { text/html html; }\n' > "$C/inc/mime.types"
printf 'server { listen 80; include snippets/tls.conf; }\n' > "$C/inc/conf.d/a.conf"
printf 'server { listen 81; }\n' > "$C/inc/conf.d/b.conf"
printf 'server { listen 443 ssl http2; }\n' > "$C/inc/conf.d/ignored.conf.disabled"
printf 'location / { proxy_pass http://app; }\n' > "$C/inc/sites/site one.conf"
printf 'listen 8443 ssl http2;\n' > "$C/inc/snippets/tls.conf"
det "$V" "$C/inc/nginx.conf"
check "includes: wildcard, nested, quoted, relative to the main config" 1 \
    "http/2 enabled: listen 8443 ssl http2" "!partly read"
rm "$C/inc/snippets/tls.conf"
det "$V" "$C/inc/nginx.conf"
check "a missing include makes a negative unknown" 2 "=CVE-2026-123007: unknown" "partly read" \
    "part of the configuration could not be read"
printf 'listen 8443 ssl http2;\n' > "$C/inc/conf.d/c.conf"
sed -i 's/listen 81;/listen 81 ssl http2;/' "$C/inc/conf.d/b.conf"
det "$V" "$C/inc/nginx.conf"
check "a missing include does not hide what was found" 1 "=CVE-2026-123007: impacted"

cat > "$C/midline.conf" <<EOF
events {}
http { server { listen 80; include $C/static-extra.conf; } }
EOF
printf 'listen 8443 ssl http2;\n' > "$C/static-extra.conf"
det "$V" "$C/midline.conf"
check "an include that shares its line with other directives" 1 "http/2 enabled: listen 8443 ssl http2" "!partly read"

det "$V" "$C/no-such.conf"
check "an unreadable config is unknown" 2 "cannot read $C/no-such.conf" "=CVE-2026-123007: unknown"

printf 'events {}\r\nhttp {\r\n    server {\r\n        listen 443 ssl http2;\r\n    }\r\n}\r\n' > "$C/crlf.conf"
det "$V" "$C/crlf.conf"
check "CRLF line endings" 1 "=CVE-2026-123007: impacted"

cat > "$C/unbalanced.conf" <<'EOF'
events {}
http { server { listen 80;
EOF
det "$V" "$C/unbalanced.conf"
check "unbalanced braces make a negative unknown" 2 "partly read"

{
    echo 'events {}'
    echo 'http {'
    i=0
    while [ "$i" -lt 4000 ]; do
        echo "    server { listen 80; server_name s$i.example; location / { root /srv/$i; } # c"
        echo "    }"
        i=$((i + 1))
    done
    echo '    server { listen 443 ssl http2; location / { proxy_pass http://app; } }'
    echo '}'
} > "$C/big.conf"
t0=$(date +%s)
det "$V" "$C/big.conf"
t1=$(date +%s)
check "an 8000 line config" 1 "=CVE-2026-123633: impacted"
report "$([ $((t1 - t0)) -lt 60 ] && echo 1 || echo 0)" "an 8000 line config is read in under a minute" "took $((t1 - t0))s"

OLDPWD_T=$PWD
cd "$C" || exit 1
run bash "$S" --no-procs --no-disk --no-kernel -b "$V" -c h2.conf
cd "$OLDPWD_T" || exit 1
check "a relative -c is relative to the current directory" 1 "=CVE-2026-123007: impacted"

echo "## 3. --root, packages and changelogs"
R="$WORK/rootfs"
mkdir -p "$R/usr/sbin" "$R/etc/nginx/conf.d" "$R/data" "$R/var/lib/dpkg/info" "$R/usr/share/doc/nginx-core"
mkbin "$R/usr/sbin/nginx" "nginx version: nginx/1.24.0 (Ubuntu)" "$ALL --with-debug" old
cat > "$R/etc/nginx/nginx.conf" <<'EOF'
events {}
http { include /etc/nginx/conf.d/*.conf; }
EOF
ln -s /data/site.conf "$R/etc/nginx/conf.d/site.conf"
printf 'server { listen 443 ssl http2; location / { proxy_pass http://app; } }\n' > "$R/data/site.conf"
printf '/usr/sbin/nginx\n/etc/nginx\n' > "$R/var/lib/dpkg/info/nginx-core.list"
cat > "$R/var/lib/dpkg/status" <<'EOF'
Package: libc6
Status: install ok installed
Version: 2.39-0ubuntu8

Package: nginx-core
Status: install ok installed
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Version: 1.24.0-2ubuntu7.5
EOF
rdet() { run bash "$S" --no-procs --no-disk --no-kernel -r "$R" -b /usr/sbin/nginx "$@"; }

rdet
check "--root: package, default config path, absolute symlink kept inside the root" 1 \
    "package nginx-core=1.24.0-2ubuntu7.5" "http/2 enabled: listen 443 ssl http2" "!partly read"

run env NGINX2ROOT_FIXED_PKGS="other=1 nginx-core=1.24.0-2ubuntu7.5" bash "$S" --no-procs --no-disk --no-kernel -r "$R" -b /usr/sbin/nginx
check "NGINX2ROOT_FIXED_PKGS exact match" 0 "package listed as fixed"

run env NGINX2ROOT_FIXED_PKGS="nginx-core=1.24.0-2ubuntu7.9" bash "$S" --no-procs --no-disk --no-kernel -r "$R" -b /usr/sbin/nginx
check "NGINX2ROOT_FIXED_PKGS newer than installed" 1

if command -v dpkg >/dev/null 2>&1; then
    run env NGINX2ROOT_FIXED_PKGS="nginx-core=1.24.0-2ubuntu7.3" bash "$S" --no-procs --no-disk --no-kernel -r "$R" -b /usr/sbin/nginx
    check "NGINX2ROOT_FIXED_PKGS older than installed (dpkg ordering)" 0 "package listed as fixed"
else
    echo "SKIP  dpkg ordering (no dpkg here)"
fi

printf 'nginx (1.24.0-2ubuntu7.5) noble-security; urgency=medium\n\n  * SECURITY UPDATE: HTTP/2 window overflow\n    - CVE-2026-123007\n' \
    | gzip > "$R/usr/share/doc/nginx-core/changelog.Debian.gz"
rdet
check "changelog names one CVE: only that one is cleared" 1 \
    "CVE-2026-123007: not impacted (fix named in the package changelog)" "=CVE-2026-123633: impacted" \
    "package changelog names CVE-2026-123007"

printf 'nginx (1.24.0-2ubuntu7.6) noble-security; urgency=medium\n\n  * SECURITY UPDATE\n    - CVE-2026-123007 CVE-2026-123633 CVE-2026-121810\n    - CVE-2026-123634\n    - CVE-2026-113425\n' \
    | gzip > "$R/usr/share/doc/nginx-core/changelog.Debian.gz"
rdet
check "changelog names all five" 0 "fix named in the package changelog"

printf 'nginx (1.24.0-2ubuntu7.5) noble; urgency=medium\n\n  * CVE-2025-23419 and nothing else\n' \
    | gzip > "$R/usr/share/doc/nginx-core/changelog.Debian.gz"
rdet
check "changelog without these CVEs clears nothing" 1 "=CVE-2026-123007: impacted" "!package changelog names"

rm -rf "$R/usr/share/doc/nginx-core"
mkdir -p "$R/usr/share/doc/nginx-common"
ln -s nginx-common "$R/usr/share/doc/nginx-core"
printf 'nginx (1.24.0-2ubuntu7.6) noble-security\n  * CVE-2026-123007 CVE-2026-123633\n' \
    | gzip > "$R/usr/share/doc/nginx-common/changelog.Debian.gz"
rdet
check "changelog found through a linked doc directory" 0 "=CVE-2026-123633: not impacted"

run bash "$S" --no-procs --no-disk --no-kernel -r "$R" -b /usr/sbin/missing
check "--root with a missing binary" 2 "not a file"

A="$WORK/alpine"
mkdir -p "$A/usr/sbin" "$A/etc/nginx" "$A/lib/apk/db"
mkbin "$A/usr/sbin/nginx" "nginx version: nginx/1.26.2" "$ALL" old
cp "$C/h2.conf" "$A/etc/nginx/nginx.conf"
cat > "$A/lib/apk/db/installed" <<'EOF'
P:musl
V:1.2.5-r0
F:lib
R:ld-musl-x86_64.so.1

P:nginx
V:1.26.2-r0
m:Jakub Jirutka <jakub@jirutka.cz>
F:etc/nginx
R:nginx.conf
F:usr/sbin
R:nginx
EOF
run bash "$S" --no-procs --no-disk --no-kernel -r "$A" -b /usr/sbin/nginx
check "apk package database" 1 "package nginx=1.26.2-r0"
run env NGINX2ROOT_FIXED_PKGS="nginx=1.26.2-r0" bash "$S" --no-procs --no-disk --no-kernel -r "$A" -b /usr/sbin/nginx
check "apk package listed as fixed" 0 "package listed as fixed"

echo "## 4. running processes"
if [ "$(uname -s)" = Linux ]; then
    P="$WORK/proc"
    mkdir -p "$P/sbin" "$P/sbin2" "$P/pfx/conf" "$P/pfx2/conf"
    cp "$C/h2.conf" "$P/pfx/conf/nginx.conf"
    cp "$C/mail.conf" "$P/pfx2/conf/alt.conf"
    cp "$C/static.conf" "$P/static.conf"
    mkfifo "$P/fifo"
    mkfake() {
        cp "$(command -v bash)" "$1"
        {
            printf '\0nginx version: nginx/1.31.8\n\0'
            printf 'configure arguments: --prefix=%s --conf-path=%s/conf/nginx.conf --with-http_v2_module --with-http_v3_module --with-mail\n\0' "$P/pfx" "$P/pfx"
            printf 'could not cancel %%V resolving\0'
        } >> "$1"
        chmod 755 "$1"
    }
    FAKE="$P/sbin/nginx"
    mkfake "$FAKE"
    printf 'read -r _ < "$1"\n' > "$P/idle.sh"
    cat > "$P/master.sh" <<'EOF'
( exec -a "nginx: worker process" "$N2R_FAKE" "$N2R_DIR/idle.sh" "$1" ) &
( exec -a "nginx: worker process is shutting down" "$N2R_FAKE" "$N2R_DIR/idle.sh" "$1" ) &
read -r _ < "$1"
EOF
    start_master() {
        local f=$1 a=$2 i
        ( N2R_FAKE=$f N2R_DIR=$P exec -a "nginx: master process $f $a" "$f" "$P/master.sh" "$P/fifo" ) &
        MPID=$!
        PIDS="$PIDS $MPID"
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
            [ "$(pgrep -P "$MPID" 2>/dev/null | wc -l)" -ge 2 ] && return 0
            sleep 0.25
        done
        echo "warning: master $MPID has no workers yet"
    }
    stop_master() { pkill -9 -P "$1" 2>/dev/null; kill -9 "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
    scan() { run bash "$S" --no-disk --no-kernel "$@"; }

    start_master "$FAKE" "-c $P/pfx/conf/nginx.conf"
    scan
    ALLOUT=$OUT
    n=$(printf '%s\n' "$ALLOUT" | grep -c "^$FAKE (pid ")
    report "$([ "$n" -eq 1 ] && echo 1 || echo 0)" "one block for the master, none for its workers" "got $n blocks"
    block "$MPID"
    check_block "titled master: binary from /proc, config from -c" "$FAKE (pid $MPID)" \
        "version: nginx/1.31.8" "CVE-2026-123007: impacted" "CVE-2026-123633: impacted" " => impacted" \
        "note: 1 old worker(s) still shutting down" "!replaced on disk"
    stop_master "$MPID"

    start_master "$FAKE" "-p $P/pfx2 -c conf/alt.conf -g daemon off;"
    scan
    block "$MPID"
    check_block "master with -p and a relative -c" "CVE-2026-113425: impacted" "CVE-2026-123007: not impacted"
    stop_master "$MPID"

    start_master "$FAKE" ""
    scan
    block "$MPID"
    check_block "master without -c uses the built-in config path" "CVE-2026-123007: impacted"
    stop_master "$MPID"

    FAKE2="$P/sbin2/nginx"
    mkfake "$FAKE2"
    start_master "$FAKE2" "-c $P/pfx/conf/nginx.conf"
    rm -f "$FAKE2"
    scan
    block "$MPID"
    check_block "binary replaced on disk: the running copy is still read" "$FAKE2 (pid $MPID)" \
        "CVE-2026-123007: impacted" "note: the binary was replaced on disk" "Restart nginx"
    stop_master "$MPID"

    "$FAKE" "$P/idle.sh" "$P/fifo" &
    SPID=$!
    PIDS="$PIDS $SPID"
    sleep 0.5
    scan
    block "$SPID"
    check_block "untitled process (master_process off)" "$FAKE (pid $SPID)" "CVE-2026-123007: impacted"
    kill -9 "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null

    "$FAKE" "$P/idle.sh" "$P/fifo" -t &
    SPID=$!
    PIDS="$PIDS $SPID"
    sleep 0.5
    scan
    block "$SPID"
    report "$([ -z "$OUT" ] && echo 1 || echo 0)" "a one-shot nginx -t is not reported" "it was"
    kill -9 "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null

    start_master "$FAKE" "-c $P/static.conf"
    scan -b "$FAKE" -c "$P/pfx/conf/nginx.conf"
    block "$MPID"
    check_block "a running master keeps its own config when -c is given for -b" "CVE-2026-123007: not impacted"
    stop_master "$MPID"

    run bash "$S"
    ok=1
    case "$CODE" in 0|1|2) ;; *) ok=0 ;; esac
    [ "$LAST" = "$(verdict "$CODE")" ] || ok=0
    has "host kernel" "sctp:" "this host" || ok=0
    report "$ok" "default full run: consistent exit code, verdict and kernel line" "exit $CODE, last '$LAST'"
else
    echo "SKIP  process tests (not Linux)"
fi

echo "## 5. busybox tools"
if command -v busybox >/dev/null 2>&1; then
    BB="$WORK/bb"
    mkdir -p "$BB"
    for t in awk grep sed tr cut cat readlink mktemp gzip head; do
        busybox "$t" --help >/dev/null 2>&1 || true
        ln -s "$(command -v busybox)" "$BB/$t"
    done
    bdet() { local b=$1 c=$2; shift 2; run env PATH="$BB:$PATH" bash "$S" --no-procs --no-disk --no-kernel -b "$b" -c "$c" "$@"; }
    bdet "$V" "$C/h2.conf"
    check "busybox: version and http/2" 1 "version: nginx/1.31.8" "=CVE-2026-123633: impacted"
    bdet "$V" "$C/lua.conf"
    check "busybox: Lua block" 1 "http/2 enabled: listen 8443 ssl http2" "=CVE-2026-113425: not impacted"
    bdet "$V" "$C/escapes.conf"
    check "busybox: escapes" 1 "!partly read"
    bdet "$V" "$C/inc/nginx.conf"
    check "busybox: includes" 1 "=CVE-2026-123007: impacted"
    bdet "$V" "$C/mail.conf"
    check "busybox: mail" 1 "=CVE-2026-113425: impacted"
    bdet "$B/backport" "$C/h2.conf"
    check "busybox: marker" 2 "probably a backport"
    run env PATH="$BB:$PATH" bash "$S" --no-procs --no-disk --no-kernel -r "$R" -b /usr/sbin/nginx
    check "busybox: --root, dpkg and gzip changelog" 0 "package nginx-core=1.24.0-2ubuntu7.5" "=CVE-2026-123633: not impacted"
    run env PATH="$BB:$PATH" bash "$S" --no-procs --no-disk --no-kernel -r "$A" -b /usr/sbin/nginx
    check "busybox: apk database" 1 "package nginx=1.26.2-r0"
else
    echo "SKIP  busybox tests (no busybox here)"
fi

echo "## 6. real nginx binaries"
start_real() {
    local bin=$1 d=$2 port=$3 i
    mkdir -p "$d/conf" "$d/logs" "$d/tmp"
    cat > "$d/conf/nginx.conf" <<EOF
pid nginx.pid;
error_log logs/error.log;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path tmp/body;
    proxy_temp_path tmp/proxy;
    fastcgi_temp_path tmp/fastcgi;
    uwsgi_temp_path tmp/uwsgi;
    scgi_temp_path tmp/scgi;
    include extra/*.conf;
    server {
        listen 127.0.0.1:$port;
        http2 on;
        location / { proxy_pass http://127.0.0.1:9; }
    }
}
EOF
    "$bin" -p "$d" -c conf/nginx.conf -g 'daemon off;' >/dev/null 2>&1 &
    RPID=$!
    PIDS="$PIDS $RPID"
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -s "$d/nginx.pid" ] && return 0
        sleep 0.25
    done
    echo "warning: $bin did not start"; cat "$d/logs/error.log" 2>/dev/null
}
if [ -n "$REAL_VULN" ] && [ -x "$REAL_VULN" ]; then
    want=$("$REAL_VULN" -v 2>&1 | sed 's/^nginx version: //')
    start_real "$REAL_VULN" "$WORK/real1" 18471
    run bash "$S" --no-disk --no-kernel
    block "$RPID"
    check_block "real unpatched nginx, running" "(pid $RPID)" "version: $want" \
        "unpatched resolver code in the binary" "CVE-2026-123007: impacted (http/2 enabled: http2 on)" \
        "CVE-2026-123633: impacted" "CVE-2026-113425: not impacted" " => impacted"
    kill "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null
    det "$REAL_VULN" "$C/mail.conf"
    check "real unpatched nginx, mail config" 1 "version: $want" "=CVE-2026-113425: impacted"
else
    echo "SKIP  real unpatched nginx (--real-vulnerable not given)"
fi
if [ -n "$REAL_FIXED" ] && [ -x "$REAL_FIXED" ]; then
    want=$("$REAL_FIXED" -v 2>&1 | sed 's/^nginx version: //')
    start_real "$REAL_FIXED" "$WORK/real2" 18472
    run bash "$S" --no-disk --no-kernel
    block "$RPID"
    check_block "real fixed nginx, running" "(pid $RPID)" "version: $want" "has the fixes" " => not impacted"
    kill "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null
    run env NGINX2ROOT_FIXED_IN="" bash "$S" --no-procs --no-disk --no-kernel -b "$REAL_FIXED" -c "$C/h2.conf"
    check "real fixed nginx carries the patch marker" 2 "probably a backport"
else
    echo "SKIP  real fixed nginx (--real-fixed not given)"
fi

echo "## 7. containers"
if [ -n "$IMAGE" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    CN="n2rt-$$"
    cscan() {
        run docker run --rm -i --privileged --pid=host "$@" "$SCAN_IMAGE" bash -s -- --no-disk < "$S"
    }
    pkgv=$(docker run --rm "$IMAGE" sh -c "dpkg-query -W -f='\${Version}' nginx 2>/dev/null" 2>/dev/null)
    imgver=$(docker run --rm "$IMAGE" nginx -v 2>&1 | sed 's/^nginx version: //')

    docker run -d --name "$CN-stock" --hostname "$CN-stock" "$IMAGE" >/dev/null
    CONTAINERS="$CONTAINERS $CN-stock"
    docker create --name "$CN-h2" --hostname "$CN-h2" "$IMAGE" >/dev/null
    CONTAINERS="$CONTAINERS $CN-h2"
    cat > "$WORK/h2c.conf" <<'EOF'
server {
    listen 8443 http2;
    location / { proxy_pass http://127.0.0.1:9; }
}
EOF
    docker cp "$WORK/h2c.conf" "$CN-h2:/etc/nginx/conf.d/h2c.conf" >/dev/null
    docker start "$CN-h2" >/dev/null
    sleep 2
    p1=$(docker inspect -f '{{.State.Pid}}' "$CN-stock")
    p2=$(docker inspect -f '{{.State.Pid}}' "$CN-h2")

    cscan
    FULL=$OUT
    has "host kernel" "sctp:"
    report "$([ $? -eq 0 ] && echo 1 || echo 0)" "container scan prints the kernel line" "missing"
    OUT=$FULL; block "$p1"
    check_block "stock container: read through /proc/PID/root, nothing enabled" \
        "/usr/sbin/nginx (pid $p1, container $CN-stock)" "version: $imgver" \
        "CVE-2026-123007: not impacted" " => not impacted"
    [ -n "$pkgv" ] && { OUT=$FULL; block "$p1"; check_block "stock container: package from its dpkg database" "package nginx=$pkgv"; }
    OUT=$FULL; block "$p2"
    check_block "container with http/2 and proxy_pass" "(pid $p2, container $CN-h2)" \
        "CVE-2026-123007: impacted (http/2 enabled: listen 8443 http2)" "CVE-2026-123633: impacted" " => impacted"

    if [ -n "$pkgv" ]; then
        cscan -e NGINX2ROOT_FIXED_PKGS="nginx=$pkgv"
        block "$p2"
        check_block "container package listed as fixed" "package listed as fixed" " => not impacted"
    fi

    docker exec "$CN-h2" sh -c 'cp /usr/sbin/nginx /tmp/nginx && chmod 755 /tmp/nginx' >/dev/null 2>&1
    docker exec -d "$CN-h2" /tmp/nginx -c /etc/nginx/nginx.conf -g 'daemon off; pid /tmp/n.pid;' >/dev/null 2>&1
    before=$(docker exec "$CN-h2" sh -c 'ls /tmp | wc -l')
    cscan
    after=$(docker exec "$CN-h2" sh -c 'ls /tmp | wc -l')
    report "$([ "$before" = "$after" ] && echo 1 || echo 0)" "scan leaves the container's /tmp untouched" "$before files before, $after after"
    for c in "$CN-stock" "$CN-h2"; do docker rm -f "$c" >/dev/null 2>&1; done
else
    echo "SKIP  container tests (--container-image not given, or no docker)"
fi

echo "## 8. ssh wrapper"
SSHW="$(dirname "$S")/ssh-nginx2root.sh"
if [ -f "$SSHW" ]; then
    FB="$WORK/fakebin"
    mkdir -p "$FB"
    cat > "$FB/ssh" <<EOF
#!/bin/sh
while [ \$# -gt 0 ]; do case "\$1" in -o) shift 2 ;; *) break ;; esac; done
host=\$1
cmd=\$2
case "\$host" in
    web1) set -- -b "$B/v1318" -c "$C/h2.conf" ;;
    web2) set -- -b "$B/v1319" -c "$C/h2.conf" ;;
    mail1) set -- -b "$B/v1318" -c "$C/mail.conf" ;;
    odd1) set -- -b "$B/backport" -c "$C/h2.conf" ;;
    pkg1) set -- -r "$A" -b /usr/sbin/nginx ;;
    *) echo "ssh: connect to host \$host: Connection refused" >&2; exit 255 ;;
esac
eval "exec \$cmd --no-procs --no-disk --no-kernel \"\\\$@\""
EOF
    chmod 755 "$FB/ssh"
    printf '# fleet\nweb1\nweb2\n\nmail1\nodd1\npkg1\ndown1\n' > "$WORK/hosts.txt"
    sshw() { run env PATH="$FB:$PATH" SUDO="" DETECT="$S" "$@"; }

    sshw sh "$SSHW" "$WORK/hosts.txt" "$WORK/results"
    ok=1
    [ "$CODE" = 1 ] || ok=0
    has "nginx2root fleet detection (6 host(s))" "impacted:     mail1 pkg1 web1" "unknown:      odd1" \
        "not impacted: web2" "down1(error (ssh/connection))" \
        "CVE-2026-123007: pkg1 web1" "CVE-2026-123633: pkg1 web1" "CVE-2026-121810: (none)" \
        "CVE-2026-113425: mail1" || ok=0
    [ -s "$WORK/results/web1.txt" ] && grep -q '^impacted$' "$WORK/results/web1.txt" || ok=0
    report "$ok" "ssh wrapper: per-host files, roll-up by verdict and by CVE, exit 1" "exit $CODE"

    sshw NGINX2ROOT_FIXED_PKGS="other=1 nginx=1.26.2-r0" sh "$SSHW" "$WORK/hosts.txt" "$WORK/results-b"
    ok=1
    has "impacted:     mail1 web1" "not impacted: pkg1 web2" "CVE-2026-123007: web1" || ok=0
    grep -q 'package listed as fixed' "$WORK/results-b/pkg1.txt" || ok=0
    report "$ok" "ssh wrapper: NGINX2ROOT_FIXED_PKGS reaches the hosts" "exit $CODE"

    sshw NGINX2ROOT_FIXED_IN="1.31.8" sh "$SSHW" "$WORK/hosts.txt" "$WORK/results-c"
    has "not impacted: mail1 web1 web2"
    report "$([ $? -eq 0 ] && echo 1 || echo 0)" "ssh wrapper: NGINX2ROOT_FIXED_IN reaches the hosts" "exit $CODE"

    sshw NGINX2ROOT_FIXED_PKGS='nginx=1; touch /tmp/x' sh "$SSHW" "$WORK/hosts.txt" "$WORK/results-d"
    report "$([ "$CODE" = 3 ] && echo 1 || echo 0)" "ssh wrapper: refuses a value it cannot pass safely" "exit $CODE"

    printf 'web2\n' > "$WORK/hosts2.txt"
    sshw sh "$SSHW" "$WORK/hosts2.txt" "$WORK/results2"
    report "$([ "$CODE" = 0 ] && echo 1 || echo 0)" "ssh wrapper: all hosts clean gives exit 0" "exit $CODE"

    printf 'web2\ndown1\n' > "$WORK/hosts3.txt"
    sshw sh "$SSHW" "$WORK/hosts3.txt" "$WORK/results3"
    report "$([ "$CODE" = 2 ] && echo 1 || echo 0)" "ssh wrapper: an unreachable host gives exit 2" "exit $CODE"
else
    echo "SKIP  ssh wrapper (not next to the detector)"
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
