# detection-scripts

> [!WARNING]
> These scripts are provided as is, without warranty of any kind, express or
> implied, including fitness for a particular purpose. Use them at your own
> risk. They are best-effort detection aids: use them as triage guidance - patch *everything* eventually.
> Review a script before running it, test it outside production first, and
> follow your organization's change-management process. Semgrep accepts no
> liability for any damage, outage or data loss from their use.

Host detection scripts for incident response. Each directory holds one
incident's scripts and a README with usage and the exit-code contract.

Instructions for individual incident scripts are contained within their respective directories.

Where possible, detections are written to be fleet-policy compatible - known unaffected hosts should return a 0 exit code, affected (or undetermined) hosts will have a nonzero exit code.

| Directory | What it detects |
|---|---|
| `CVE-2026-114938/` | JVMs exposed to the HotSpot x86-64 AVX-512 Base64 decode heap overwrite (CVE-2026-114938, JDK-8392044) |
| `CVE-2026-123633.CVE-2026-123007/` | nginx exposed to the HTTP/2 flow-control overflow (CVE-2026-123007) or use-after-free (CVE-2026-123633) with HTTP/2 on, to the resolver use-after-free (CVE-2026-123634) with a `resolver` configured, to the HTTP/3 use-after-free (CVE-2026-121810) with a QUIC listener, or to the mail proxy use-after-free (CVE-2026-113425) with a mail server |
