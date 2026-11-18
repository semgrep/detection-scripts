# nginx2root detection (CVE-2026-123007, CVE-2026-123633, CVE-2026-121810, CVE-2026-123634, CVE-2026-113425)

Fleet checks for the five nginx vulnerabilities disclosed on 2026-11-18 as
"nginx2root". Each one lets an unauthenticated remote attacker run code as the
nginx worker process. All five are fixed in nginx 1.31.9 and 1.30.7.

| CVE | What it is | Affected nginx versions |
|---|---|---|
| CVE-2026-123007 | HTTP/2 flow-control window overflow | 1.9.5 to 1.31.8 |
| CVE-2026-123633 | HTTP/2 use-after-free | 1.19.7 to 1.31.8 |
| CVE-2026-121810 | HTTP/3 use-after-free | 1.25.0 to 1.31.8 |
| CVE-2026-123634 | DNS resolver use-after-free | 0.6.18 to 1.31.8 |
| CVE-2026-113425 | Mail proxy use-after-free | 0.5.33 to 1.31.8 |

Quick start, on the host you want to check:

```sh
sudo ./linux/detect-nginx2root.sh
```

The last line of the output is `impacted`, `not impacted` or `unknown`. Above
it is one status line for each CVE.

The scripts are read-only. They do not run nginx, do not reload it, send it no
traffic, and change nothing on the host.

## Directory contents

Run the examples below from this directory.

| File | Purpose |
|---|---|
| `linux/detect-nginx2root.sh` | Host detector (bash 3.2+) |
| `linux/ssh-nginx2root.sh` | Fleet run over plain SSH |
| `linux/ansible-nginx2root.yml` | Fleet run through Ansible |
| `linux/k8s-nginx2root.yaml` | Fleet run as a privileged Kubernetes DaemonSet |
| `linux/k8s-exec-nginx2root.sh` | Fleet run with `kubectl exec` into each container |

The fleet wrappers find the detector next to themselves, so keep the files
together. The `tests/` folder holds the maintainers' test harness; it is not
needed to run any script.

## What counts as impacted

An nginx is impacted by a CVE when all three conditions hold for it:

1. **Version.** The nginx version is in that CVE's affected range (table
   above). Versions 1.31.9 and later, and 1.30.7 and later 1.30.x, are fixed.
   - OpenResty is judged on its nginx core: `openresty/1.27.1.2` is nginx
     1.27.1.
   - Tengine is judged on the nginx version it reports.
   - Angie, freenginx and other forks with their own version numbers are
     `unknown`. Check the vendor's advisory.
   - NGINX Plus is judged on the nginx version in its version string. Confirm
     the result against the F5 advisory, which lists the fixed Plus releases.
2. **No fix recorded for the package.** Linux distributions patch nginx
   without changing its version number, so an old version is not proof of an
   unpatched host. The detector treats a CVE as fixed when:
   - the package changelog names that CVE (dpkg and rpm packages), or
   - you have listed the package in `NGINX2ROOT_FIXED_PKGS` (see Usage).

   If neither applies but the binary itself carries one of the fixes, the
   result is `unknown` rather than `impacted`, with "probably a backport" in
   the version line.
3. **Configuration.** The affected feature is switched on:

| CVE | Switched on when |
|---|---|
| CVE-2026-123007 | HTTP/2 is enabled: `http2` on a `listen` directive, or `http2 on;` in a server or inherited from `http {}`. |
| CVE-2026-123633 | HTTP/2 is enabled and requests are passed to a backend: `proxy_pass`, `grpc_pass`, `fastcgi_pass`, `uwsgi_pass`, `scgi_pass` or `memcached_pass`. |
| CVE-2026-121810 | A `listen ... quic` directive (HTTP/3) and requests passed to a backend as above. |
| CVE-2026-123634 | A `resolver` directive, a `*_pass` target that contains a variable, and a directive that creates subrequests: `mirror`, `ssi on`, `auth_request`, `add_before_body` or `add_after_body`. |
| CVE-2026-113425 | A `mail {}` block with at least one `server`. |

Lua and njs code can open backend connections, look up names through the
`resolver` and make subrequests, and none of that can be read from the
configuration. Where a CVE's directives are only partly present and Lua or
njs handlers are configured, that CVE is reported `unknown`, not
`not impacted`. The same goes for CVE-2026-123634 when `resolver` and a
variable `*_pass` are present without a subrequest directive.

A feature that is compiled out (for example no `--with-http_v2_module`) rules
its CVE out regardless of the configuration.

The detector reads all of this without running nginx:

- The version and build options are read from the nginx binary. For a running
  nginx that is the binary in memory, so the answer is right even when the
  file on disk was replaced by an upgrade and nginx was not restarted.
- The configuration is read from disk, starting at the file the running nginx
  was started with and following every `include`. Comments, quoted strings and
  Lua code blocks are skipped.
- For containers, files are read through `/proc/PID/root`. Nothing is run
  inside the container.

The configuration on disk is what nginx loads at its next reload. If someone
edited it without reloading, the running configuration may differ.

## Output

```
nginx2root check: the five CVEs fixed in nginx 1.31.9 and 1.30.7
Each nginx gets a status per CVE: impacted, not impacted or unknown (could not check).
host: Linux x86_64

/usr/sbin/nginx (pid 4159, container web-6c9f7d8b5-x2x7q)
  version: nginx/1.24.0 (Ubuntu), package nginx=1.24.0-2ubuntu7.19: affected range; a backport cannot be seen in a debug build
  CVE-2026-123007: impacted (http/2 enabled: listen 8443 ssl http2)
  CVE-2026-123633: impacted (http/2 with proxy_pass http://127.0.0.1:9)
  CVE-2026-121810: not impacted (not affected before 1.25.0)
  CVE-2026-123634: not impacted (no resolver in http{})
  CVE-2026-113425: not impacted (no mail{} servers)
  => impacted (CVE-2026-123007, CVE-2026-123633)

host kernel 6.8.0-87-generic (the separate, unpatched root step; not part of the verdict)
  sctp: reachable: sctp is not loaded but loads on demand (no "install sctp /bin/false" in modprobe.d)

this host
CVE-2026-123007: impacted
CVE-2026-123633: impacted
CVE-2026-121810: not impacted
CVE-2026-123634: not impacted
CVE-2026-113425: not impacted

impacted
```

Each nginx is one block: its version, a status for each CVE with the reason
in brackets, and its own result after `=>`. A status is one of:

- `impacted`: all three conditions hold.
- `not impacted`: at least one condition rules it out. The reason says which.
- `unknown`: something could not be checked. The reason says what.

The title line names the binary and where it was found:

- `pid N`: a running nginx.
- `container <name>`: a running nginx in a container. The name is the pod name
  in Kubernetes and the short container ID in Docker.
- `chroot`: a running nginx in a chroot.
- `host`: a running nginx on the node itself, seen from the DaemonSet.
- `installed, not running`: found on disk.
- `-b`: a binary passed on the command line.

After the blocks, `this host` gives one line per CVE with the worst status
found in any nginx, and the last line is the overall verdict. `-q` prints only
those five lines and the verdict.

A block may also carry a note:

- **"the binary was replaced on disk after this nginx started"**: nginx was
  upgraded but not restarted. The result describes the old code that is still
  running. Restart nginx; a reload is not enough.
- **"N old worker(s) still shutting down"**: workers left over from a reload
  keep the previous configuration until their connections close.
- **"part of the configuration could not be read or parsed"**: a
  `not impacted` would be a guess, so the status is `unknown` instead.

The `host kernel` block is extra information. Running code as the nginx
worker is the nginx bug; becoming root needs a second, separate bug in the
Linux kernel's SCTP code, which had no fix on 2026-11-18. The line says
whether SCTP can be reached on this kernel. It does not change the verdict.

## Exit codes

| Code | Last line | Meaning |
|---|---|---|
| 0 | `not impacted` | no nginx is impacted by any of the five CVEs, or no nginx was found |
| 1 | `impacted` | at least one nginx is impacted by at least one CVE |
| 2 | `unknown` | at least one nginx could not be evaluated and none is impacted |
| 3 | (usage) | bad arguments |

## Usage

```sh
sudo ./linux/detect-nginx2root.sh             # every running and installed nginx
sudo ./linux/detect-nginx2root.sh -q          # five status lines and the verdict
sudo ./linux/detect-nginx2root.sh --no-disk   # running nginx only
./linux/detect-nginx2root.sh --no-procs --no-disk -b /opt/app/sbin/nginx -c /opt/app/conf/nginx.conf
./linux/detect-nginx2root.sh --no-procs --no-disk -r /mnt/image -b /usr/sbin/nginx
```

| Option | Effect |
|---|---|
| `-q`, `--quiet` | print only the five status lines and the verdict |
| `-v`, `--verbose` | print diagnostic detail |
| `-b`, `--binary PATH` | also check this nginx binary (repeatable) |
| `-c`, `--conf PATH` | configuration file for binaries that are not running |
| `-r`, `--root DIR` | `-b` and `-c` are paths inside `DIR`, an unpacked image or a mounted disk |
| `--no-procs` | skip running processes |
| `--no-disk` | skip installed binaries on disk |
| `--no-kernel` | skip the `host kernel` block |

Run as root. Without root the script cannot read nginx processes owned by
other users (nginx usually starts as root) or anything in a container, and
those come out `unknown`.

As of 2026-11-18 no distribution had shipped a fixed package, so none is
built in. When yours does, either the package changelog names the CVEs and
the detector picks that up by itself, or you tell it:

```sh
sudo NGINX2ROOT_FIXED_PKGS="nginx=1.24.0-2ubuntu7.20" ./linux/detect-nginx2root.sh
```

- `NGINX2ROOT_FIXED_PKGS` takes `name=version` entries, space separated. Use
  the package name and version shown in the detector's version line. An exact
  match is `not impacted`. For Debian and Ubuntu packages, a newer installed
  version matches too.
- `NGINX2ROOT_FIXED_IN` replaces the first fixed nginx releases (default
  `"1.30.7 1.31.9"`). The highest entry also covers every later release line.

The fleet wrappers pass these settings on to the hosts they check. Each
section under Fleet runs shows how.

## Coverage

| | Covered |
|---|---|
| Running nginx, with the `-c` and `-p` it was started with | yes |
| nginx in containers (Docker, containerd, Kubernetes pods) and chroots | yes, as root |
| `nginx`, `openresty`, `angie` and `tengine` on PATH and in common install directories | yes |
| nginx upgraded on disk but not restarted | yes, the running copy is checked |
| Backports recorded in a dpkg changelog (Debian, Ubuntu) | yes |
| Backports recorded in an rpm changelog (RHEL family, SUSE) | yes, where the `rpm` command is available to the script |
| Backports in Alpine packages | no changelog on disk; use `NGINX2ROOT_FIXED_PKGS` |
| Unpacked images and mounted disks | yes, with `-r` |

Not covered:

- Windows and macOS.
- Directives passed with `-g` on the nginx command line.
- Configuration that exists only in memory, and anything Lua or njs code does
  at run time. See the note under the configuration table for how that is
  reported.
- Third-party modules that open backend connections or create subrequests.
- Stopped containers and images. Unpack one and use `-r`.
- Managed services that run nginx for you, such as a cloud load balancer or a
  CDN. Check those vendors' advisories.
- Signs of an attack. These scripts check exposure, not compromise.

The configuration check looks at each nginx as a whole, not at each virtual
server. HTTP/2 on one server and `proxy_pass` on another counts for
CVE-2026-123633. That leans toward `impacted`.

## Fleet runs

Wrappers that run `detect-nginx2root.sh` on many hosts and roll up the
verdicts. Each one keeps the detector's exit-code contract.

### SSH

`ssh-nginx2root.sh` needs no Ansible and installs nothing: the detector is
piped to each host's bash over stdin and run there, so nothing is copied to
or left on the target.

```sh
sh linux/ssh-nginx2root.sh hosts.txt results          # one host or user@host per line
PARALLEL=20 sh linux/ssh-nginx2root.sh hosts.txt
DETECT_ARGS="-q" sh linux/ssh-nginx2root.sh hosts.txt  # save just the status lines
SUDO="" sh linux/ssh-nginx2root.sh hosts.txt           # run as the login user (less coverage)
NGINX2ROOT_FIXED_PKGS="nginx=1.24.0-2ubuntu7.20" sh linux/ssh-nginx2root.sh hosts.txt
```

It needs key-based SSH and, for full coverage, passwordless sudo and bash on
the targets. `NGINX2ROOT_FIXED_PKGS` and `NGINX2ROOT_FIXED_IN`, when set, are
passed to every host. Each host's output goes to `results/<host>.txt`. At the end it
prints the hosts by verdict and the impacted hosts for each CVE. It exits `1`
if any host is impacted, else `2` if any host is unknown or unreachable, else
`0`.

### Ansible

`ansible-nginx2root.yml` runs the detector on every host in the inventory.
No agent is installed: Ansible copies the detector to a temp path, runs it,
and removes it.

```sh
ansible-playbook -i inventory linux/ansible-nginx2root.yml
ansible-playbook -i inventory linux/ansible-nginx2root.yml -e detect_args="-q"
ansible-playbook -i inventory linux/ansible-nginx2root.yml -e fixed_pkgs="nginx=1.24.0-2ubuntu7.20"
```

`fixed_pkgs` sets `NGINX2ROOT_FIXED_PKGS` on every host.
Each host's output is saved to `./results/<host>.txt`, and a host list per
verdict prints at the end. Exit codes `1` (impacted) and `2` (unknown) are
verdicts and do not fail the play; `3` (usage error) does.

### Kubernetes

Two methods, both running the same detector:

- `k8s-nginx2root.yaml` is a DaemonSet. One pod per node with `hostPID` and
  `privileged`, so the detector sees every nginx on the node, including
  ingress controllers and nginx in other pods. Nothing is copied into or run
  inside workloads. The detector is mounted from a ConfigMap:

  ```sh
  kubectl create namespace nginx2root
  kubectl -n nginx2root create configmap detect --from-file=linux/detect-nginx2root.sh
  kubectl apply -f linux/k8s-nginx2root.yaml
  kubectl -n nginx2root rollout status daemonset/nginx2root
  kubectl -n nginx2root logs -l app=nginx2root --tail=-1 --prefix --max-log-requests=500
  kubectl delete namespace nginx2root
  ```

  The pod is privileged by design. Review the manifest before applying it and
  delete the namespace when you have your results. Each block names the pod,
  and each pod's log is the result for its node. To list fixed packages, fill
  in the `NGINX2ROOT_FIXED_PKGS` value in the manifest.

- `k8s-exec-nginx2root.sh` is for clusters that forbid privileged pods. It
  runs the detector inside every running container with `kubectl exec`. It
  needs only the right to list pods and exec into them. Containers without
  bash are reported `unknown`; use the DaemonSet for those.
  `NGINX2ROOT_FIXED_PKGS` and `NGINX2ROOT_FIXED_IN`, when set, are passed to
  every container.

  ```sh
  sh linux/k8s-exec-nginx2root.sh > results.txt              # all namespaces
  sh linux/k8s-exec-nginx2root.sh -n ingress > results.txt   # one namespace
  ```

## If a host is impacted

1. **Upgrade** nginx to 1.31.9 or 1.30.7 or later, or to the package your
   distribution lists as fixing these CVEs. For OpenResty and other forks,
   take the vendor release that includes these fixes. For NGINX Plus, follow
   the F5 advisory.
2. **Restart nginx.** A reload does not replace the running binary. Run the
   detector again afterwards: it tells you if an old copy is still running.
3. **If you cannot upgrade yet**, switch off the feature named in the status
   line. This blocks the known attack path; it is not a fix.

   | CVE | Temporary mitigation |
   |---|---|
   | CVE-2026-123007, CVE-2026-123633 | Turn HTTP/2 off: remove `http2` from every `listen` directive and, on nginx 1.25.1 and later, set `http2 off;`. Clients fall back to HTTP/1.1; native gRPC clients stop working. |
   | CVE-2026-121810 | Remove the `listen ... quic` directives and stop advertising HTTP/3 in `Alt-Svc`. |
   | CVE-2026-123634 | Point `*_pass` at a fixed `upstream` group instead of a variable, so no DNS lookup happens during a request. |
   | CVE-2026-113425 | Keep untrusted clients away from the mail proxy: bind it to loopback or restrict it with a firewall. |

   After a configuration change, reload nginx and run the detector again. Old
   workers keep the previous configuration until they exit, and the detector
   notes when any are left.
4. **Kernel.** On hosts that do not use SCTP, add `install sctp /bin/false` to
   a file under `/etc/modprobe.d/`. This stops the module from loading. It
   does not unload a module that is already loaded and has no effect where
   SCTP is built into the kernel.
