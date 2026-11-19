# phpAftershell — PHP November 2026 critical-release exposure detection

Host detection for the **seven CRITICAL (CVSS v4.0 9.2) vulnerabilities** fixed in the coordinated PHP
security release of **19 November 2026** (PHP **8.5.13 / 8.4.28 / 8.3.37 / 8.2.36**). The headline bug,
**phpAftershell (CVE-2026-126714)** — unauthenticated RCE through a partially-overwritten `files` session
file — gives this folder its name; the detector checks that CVE **and the other six** criticals of the
same release in one pass.

> These scripts are **best-effort triage aids, provided as is, without warranty of any kind.** They read
> PHP versions, effective `php.ini`, web-server config and (optionally) application code. They make no
> changes, no network calls, and contain no exploit code. Always confirm against the official advisories.

## The seven CRITICALs

| CVE | Component → impact | Branches | Precondition gate |
|---|---|---|---|
| CVE-2026-126714 (phpAftershell) | Partially-overwritten session file → **RCE** (no app gadget needed) | 8.2–8.5 | `session.save_handler=files` (default) + `upload_progress` on |
| CVE-2026-129289 | PHP-FPM request smuggling via unread body → **RCE** | 8.2–8.5 | front-end FastCGI keep-alive + a route that doesn't fully read the body |
| CVE-2026-115560 | Session serializer mismatch → **RCE** (public PoC) | 8.2–8.5 | `upload_progress` on + mismatched `serialize_handler` (runtime switch to `php`) |
| CVE-2026-129496 | Date timezone-cache UAF → **RCE** | 8.2–8.5 (NTS) | NTS build + a startup diagnostic written to a file `error_log` |
| CVE-2026-129481 | Use-after-free after interrupted session shutdown | 8.3–8.5 | session-held resource whose close raises a fatal error (AC:H) |
| CVE-2026-129474 | Magic-method backtrace UAF → **RCE** | 8.5 only | `fatal_error_backtraces!=0` + `zend.exception_ignore_args=0` |
| CVE-2026-129182 | `last_fatal_error_backtrace` UAF after shutdown | 8.5 only | conflicting per-directory / per-request INI overrides |

Criticals fixed per version: **8.2.36 → 4**, **8.3.37 / 8.4.28 → 5**, **8.5.13 → 7**.

## Directory contents

Run the examples from this directory.

`linux/` holds a single self-contained detector and the fleet wrappers that run it. The wrappers find the
detector next to themselves and add no detection logic of their own.

| File | Purpose |
|---|---|
| `linux/detect-php-criticals.sh` | **The detector.** One file, bash 3.2+ (Linux and macOS), no dependencies beyond coreutils / grep / sed / awk / find. Checks all seven CVEs and prints a per-CVE status. |
| `linux/ssh-php-criticals.sh` | Run the detector across a list of hosts over SSH; prints `host: <verdict> (exit N)` and a roll-up. |
| `linux/ansible-php-criticals.yml` | Playbook: run the detector on every inventory host, report per host, fail impacted hosts. |
| `linux/k8s-php-criticals.yaml` | Privileged DaemonSet: run the detector against each **node's** filesystem and log the verdict. |
| `linux/k8s-exec-php-criticals.sh` | `kubectl exec` the detector into running containers that bundle PHP (application pods). |
| `linux/azure-runcommand-php-criticals.sh` | Run the detector on Azure Linux VMs with `az vm run-command`. |

A Windows PowerShell detector is planned as a follow-up; PHP production deployments are overwhelmingly
Linux (php-fpm behind nginx/Apache), and several of these issues are Linux-centric.

## Quick start

```sh
sudo ./linux/detect-php-criticals.sh              # full per-CVE report + overall verdict
sudo ./linux/detect-php-criticals.sh -v           # + the gate finding and mitigation under each CVE
sudo ./linux/detect-php-criticals.sh -q           # per-CVE lines + the verdict word only
sudo ./linux/detect-php-criticals.sh -b /opt/php/sbin/php-fpm   # also check this binary (repeatable)
sudo ./linux/detect-php-criticals.sh --json | head -n 1 | jq .  # machine output (line 1 is the JSON)

./linux/ssh-php-criticals.sh -s -H hosts.txt -P 16             # fleet sweep over SSH
```

## Output

The detector inventories PHP once and prints one line per CVE, then an overall verdict:

```
PHP criticals 2026-11-19 exposure check  (7 CVEs; fixed-in: 8.2.36 8.3.37 8.4.28 8.5.13)
host: web-01
php installs:
  /usr/sbin/php-fpm8.4               8.4.27       fpm(web)  NTS  < 8.4.28

CVE-2026-126714  IMPACTED      Session partial file overwrite
CVE-2026-129289  IMPACTED      FPM request smuggling
CVE-2026-115560  IMPACTED      Session serializer mismatch
CVE-2026-129496  UNKNOWN       Date timezone-cache UAF
CVE-2026-129481  IMPACTED      Session UAF interrupted shutdown
CVE-2026-129474  NOT_APPLICABLE Magic-method backtrace UAF
CVE-2026-129182  NOT_APPLICABLE last_fatal_error_backtrace UAF

overall: impacted  (impacted: 4  unknown: 1  not impacted: 0  not applicable: 2)
impacted
```

`NOT_APPLICABLE` means the host's PHP series is outside that CVE's branch list (e.g. the two 8.5-only CVEs
on an 8.4 host). The **last line is always exactly** `impacted`, `not impacted` or `unknown`.

## Exit codes (for fleet tooling)

```
0  not impacted   no applicable CVE is impacted on any PHP found
1  impacted       at least one CVE is impacted on at least one PHP
2  unknown        no impacted CVE, but at least one unknown (or no PHP found)
3  usage error
```

## What counts as impacted

Per CVE, the status is `IMPACTED` when the host's PHP is **below its series' 19 Nov 2026 release** *and*
the CVE's precondition is met or cannot be ruled out; `NOT_IMPACTED` when patched or the precondition is
excluded; `UNKNOWN` when the detector cannot decide (no PHP, unparseable version, EOL ≤ 8.1, a running
php-fpm master whose binary cannot be read, or mod_php / FrankenPHP which cannot be queried from the
command line); `NOT_APPLICABLE` when the series is off-branch. The detector is deliberately conservative —
it never reports `IMPACTED` from a guess about something it could not inspect.

**CLI ini ≠ web SAPI ini.** The configuration `php` reports on the command line often differs from the
php-fpm / Apache SAPI that serves traffic (the deciding settings frequently live only in the FPM pool,
`.htaccess` or `.user.ini`). The detector queries `php-fpm -i` when available and warns you to audit the
web SAPI separately.

## Mitigations (apply now; keep after patching)

- **Patch** to 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 — the only complete fix.
- `session.upload_progress.enabled=0` — removes phpAftershell (126714) and the serializer mismatch (115560).
  If upload progress is explicitly enabled, every reader and writer of a session store must use the same
  `session.serialize_handler`, set administratively and never via `ini_set()`.
- Disable FastCGI connection reuse (`fastcgi_keep_conn off` / `enablereuse=off`) — 129289.
- Send startup/error logs to syslog rather than a file, and fix the misconfig that emits them — 129496.
- `zend.exception_ignore_args=1` (the `php.ini-production` value) or `fatal_error_backtraces=0` — 129474;
  `fatal_error_backtraces=0` (set so request config can't re-enable it) + remove conflicting per-directory
  INI — 129182 (the advisory calls this a temporary workaround, not a fix).

## Limitations

- Verified with `bash -n`, a no-PHP dry run, and stub `php` / `php-fpm` binaries covering the version gate
  and each CVE gate; the real `php -i`, php-fpm pool, `/proc` master and web-server paths were additionally
  smoke-tested against a live `php:8.4-fpm` container, but not across a broad matrix of real hosts. Smoke-test
  on a representative host before fleet rollout.
- Distribution backports can carry a fix without changing `PHP_VERSION`; such hosts are reported by upstream
  version with a note to check the vendor tracker.
- EOL series (≤ 8.1) are reported `UNKNOWN` (treat as exposed); 126714 honours `PHP2026_EOL_MITIGATED=1`
  for the official EOL mitigation branches.
- Containers, statically-embedded PHP, php-cgi ini and Windows are not covered by this detector.
