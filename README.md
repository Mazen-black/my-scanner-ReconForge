# ReconForge

[![Tests](https://github.com/Mazen-black/my-scanner-ReconForge/actions/workflows/tests.yml/badge.svg)](https://github.com/Mazen-black/my-scanner-ReconForge/actions/workflows/tests.yml)

**my-scanner-ReconForge** is a Python-based network reconnaissance and vulnerability assessment tool.

A Python-based network service scanner that combines Nmap service/version detection with CVE lookups from the NVD and optional local Exploit-DB searches through Searchsploit. Results are saved as structured JSON for review.

> **Current version:** Scanner 0.10.11 · Report schema 1.16

**Status:** Educational / portfolio project. Findings are leads for manual validation, not proof that a system is vulnerable.

## Features

- Uses Nmap for port scanning and service/version detection.
- Identifies potentially sensitive exposed network services (databases, remote administration, file sharing, container APIs, and legacy cleartext protocols) with evidence, severity, and remediation guidance.
- Builds an evidence-backed technology fingerprint from observed product, version, service, TLS tunnel, CPE, and extra-info fields.
- Optional HTTP security review (`--http-probe`) inspects response headers and cookie attributes using one bounded HEAD request per recognized web service.
- Optional web intelligence (`--web-intel`) analyzes a bounded root HTML response for CMS/JavaScript-library hints and checks fixed same-origin `robots.txt` and `sitemap.xml` paths.
- Queries the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) for potentially relevant CVEs.
- Evaluates NVD CPE criteria, version bounds, nested nodes, and AND/OR/negate logic conservatively; unknown environment requirements remain unverified.
- Optionally searches the local Exploit-DB database with `searchsploit`.
- Enriches exploit references with validated Exploit-DB links, explicit CVE-title correlation, conservative platform compatibility, product/version title relevance, and safe manual validation guidance; exploit code is never executed.
- Reads only allowlisted metadata comments from the first 80 lines of local Exploit-DB files to report explicitly documented target architecture, authentication, privilege, and prerequisite hints; strict normalization maps only known values and preserves unrecognized wording as unknown raw evidence.
- Optional Nmap OS fingerprinting (`--os-detection`) adds `-O` explicitly; the HTML dashboard summarizes one OS match per host, including Nmap's match accuracy, the acceptance threshold, broad platform family, and unknown/no-match states. OS-family compatibility remains a coarse research hint, not proof of exploitability.
- Calculates a separate technical review-priority score from CVSS and NVD applicability evidence; exploit references do not increase the numeric score.
- Adjusts contextual review priority only from explicitly operator-supplied asset criticality and exposure; unknown context is neutral and open ports never imply internet reachability.
- Adds service-specific and CVE-aware remediation guidance with verification steps; it never executes remediation or invents fixed versions.
- Generates a standalone HTML dashboard with escaped untrusted values, and can render schema 1.0–1.16 envelopes, older unversioned envelopes, and legacy list reports. Newer/unknown schema versions and malformed JSON are rejected with a clear CLI error rather than silently misinterpreted.
- Supports `--no-nvd` for offline operation when NVD is unavailable.
- Produces versioned JSON reports with scan metadata, resolved hosts, summary counts, service details, matching evidence, and assessment limitations.
- Adds an evidence-confidence model that separates CVE applicability confidence from exploitability confidence, records evidence sources/reasons/gaps, and never treats CVSS severity or an Exploit-DB title match as proof of exploitability.
- Correlates Exploit-DB references only through explicit CVE identifiers found in titles, structured source fields, or duplicate observations; collapses duplicate EDB hits while retaining the evidence source for each link.
- Validates target, port ranges, result limits, and shell-safe Nmap argument parsing before scanning.
- Includes offline unit and integration tests for CPE conversion, version applicability, result classification, input validation, and report structure.

## Project architecture

The installable `src/reconforge/` package separates the scanner workflow into focused modules:

- `scanner.py` coordinates Nmap, assessment, reporting, and command-line execution.
- `targeting.py` validates targets and ports and interprets host-level Nmap OS evidence.
- `nvd.py` handles CPE query construction, NVD requests, rate limiting, and CVE applicability candidates.
- `exploitdb.py` performs local SearchSploit lookups and reads only allowlisted metadata from local exploit-file headers; it never executes exploit code.
- `web_probe.py` contains bounded HTTP header, cookie, and same-origin web-intelligence probes.
- `assessment.py` is a compatibility facade; `cpe_assessment.py` evaluates CPE/CVE applicability, `exploit_assessment.py` handles exploit-reference triage and exposure evidence, and `web_assessment.py` analyzes HTTP hardening and bounded page metadata.
- `risk.py`, `asset_context.py`, and `remediation.py` handle prioritization, operator-supplied context, and guidance.
- `report.py` writes the HTML dashboard and renders existing JSON reports.
- `summary.py` is the canonical aggregation layer used by scanner CLI host summaries, JSON output, and HTML dashboard metrics.

Root-level Python scripts remain compatibility entry points for existing workflows.

## How it works

1. Nmap identifies open ports and service/version details on the specified target.
2. The scanner builds product/CPE-based queries and retrieves candidate CVE records from NVD.
3. NVD configuration trees are evaluated with conservative three-valued logic, preserving nested AND, OR, and negate conditions.
4. Known sensitive service ports produce network-exposure observations with evidence and hardening recommendations; an open port alone is not labelled an exploitable vulnerability.
5. If Searchsploit is installed and enabled, local exploit references are searched and heuristically classified.
6. Exploit intelligence enriches those references with validated Exploit-DB links, explicit CVE-title correlation, platform/type metadata, and safe validation guidance. If the local Exploit-DB source file is available, only allowlisted key/value comments from its first 80 lines are read; source code is never evaluated or executed. Missing architecture and prerequisite details remain unknown. Every reference is marked `not_executed`.
7. The report includes the service fingerprint, CVE assessment, network exposure observations, and exploit intelligence.
8. When `--http-probe` is enabled, one HEAD request to `/` is made for each recognized HTTP service; redirects are not followed and TLS certificate verification stays enabled.
9. When `--web-intel` is enabled, bounded GET requests inspect `/`, `/robots.txt`, and `/sitemap.xml` on the same scanned host only; redirects and external asset fetching are disabled.
10. Risk priority is calculated separately from CVSS; unknown applicability is discounted, non-matches are not actionable, and Exploit-DB references do not raise the score.
11. Operator-supplied asset criticality/exposure optionally adjusts contextual review priority; unknown values remain neutral.
12. Guidance-only remediation includes service hardening and CVE validation steps without executing changes or fabricating fixed releases.
13. A versioned JSON report is written; `--html-output` optionally creates a standalone HTML dashboard.

## Requirements

- Python 3.10+
- Nmap installed and available on `PATH`
- Installable Python package and dependencies declared in `pyproject.toml`
- Optional: Searchsploit / Exploit-DB installed and available on `PATH`
- Optional: an NVD API key for a higher API request limit

## Installation

### Kali Linux / Debian-based systems

Install system tools (package names can vary by distribution):

```bash
sudo apt update
sudo apt install nmap exploitdb
```

Create a virtual environment and install Python dependencies:

Clone the released source from the default branch and install it in an isolated environment:

```bash
git clone https://github.com/Mazen-black/my-scanner-ReconForge.git
cd my-scanner-ReconForge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install .
```

Alternatively, install the published wheel directly inside an active virtual environment:

```bash
pip install https://github.com/Mazen-black/my-scanner-ReconForge/releases/download/v0.10.11/reconforge-0.10.11-py3-none-any.whl
```

Editable installation provides the `reconforge` and `reconforge-report` commands. The root-level `scanner.py` and `report.py` scripts remain available for compatibility.

If you do not use Searchsploit, omit the `exploitdb` system package and run with `--no-exploitdb`.

### Build a local Debian package (experimental)

A Debian package build script is included for Kali/Debian users who prefer `apt`-managed installation. It builds locally and does not publish an APT repository or install anything by itself:

```bash
sh packaging/build-deb.sh
sudo apt install ./dist/reconforge_0.10.11_all.deb
```

The package declares its Python and Nmap dependencies so APT can resolve them from your configured repositories. Searchsploit remains optional. The `.deb` is currently a local build artifact, not an asset attached to the GitHub Release.

## Usage

Only scan systems you own or have explicit permission to assess.

Basic scan:

```bash
reconforge --target 192.0.2.10
```

Specify ports and generate both JSON and HTML reports:

```bash
reconforge --target 192.0.2.10 --ports 1-1000 --output report.json --html-output report.html
```

Enable optional OS fingerprinting when you have authorization and the required privileges:

```bash
sudo reconforge --target 192.0.2.10 --ports 1-1000 --os-detection --output report.json
```

This option adds Nmap's -O OS-detection probe. It may require root/raw-socket privileges and can still return no reliable match. Without --os-detection, the default scan remains unchanged. ReconForge accepts only the first Nmap OS match at 90% accuracy or higher; lower-confidence or missing matches remain unknown. Broad OS-family matches are not proof of architecture or exploit compatibility.

Run without NVD requests when offline or when the NVD API is unavailable:

```bash
reconforge --target 192.0.2.10 --no-nvd --html-output offline-report.html
```

Supply asset context only when independently verified:

```bash
reconforge --target 192.0.2.10 --asset-criticality high --exposure internet --html-output report.html
```

Supported criticality values: `unknown`, `low`, `medium`, `high`, `critical`. Supported exposure values: `unknown`, `internal`, `internet`. Both default to `unknown`; the scanner does not infer internet reachability from an open port.

Enable the optional HTTP headers and cookie review (only for recognized web services):

```bash
reconforge --target 192.0.2.10 --http-probe
```

The HTTP review sends one `HEAD /` request per recognized web service, does not follow redirects, uses short timeouts, and does not disable TLS certificate verification. It records cookie names and security attributes only; cookie values are not saved. Missing security headers are hardening observations, not proof of an exploitable vulnerability.

Enable bounded web technology and site metadata discovery:

```bash
reconforge --target 192.0.2.10 --web-intel
```

This mode fetches only the root document, `/robots.txt`, and `/sitemap.xml` on the scanned host. The root response is capped at 256 KiB; robots and sitemap responses are capped at 64 KiB each. It does not follow redirects, fetch JavaScript assets, crawl links, or request URLs listed inside robots/sitemap files. CMS and JavaScript-library labels are heuristic hints from meta-generator values and asset URL patterns, not proof of installed versions. Robots directives are not access controls.

Disable the local Exploit-DB search:

```bash
reconforge --target 192.0.2.10 --no-exploitdb
```

Provide an NVD API key through an environment variable (recommended over putting a key in shell history):

```bash
export NVD_API_KEY="YOUR_NVD_API_KEY"
reconforge --target 192.0.2.10
```

You can also pass `--nvd-api-key`, but avoid saving secrets in scripts, screenshots, shell history, or reports. Get an API key from the official [NVD API site](https://nvd.nist.gov/developers/request-an-api-key).

Render an existing JSON report without running another scan (supports current versioned envelopes and legacy list reports):

```bash
reconforge-report report.json --output report.html
```

View all options:

```bash
reconforge --help
```

Replace `192.0.2.10` with a lab target or another system you are authorized to scan. The address above is reserved for documentation examples.

## Sample lab evidence

The [`evidence/`](evidence/) directory contains three complementary proof sets: (1) an authorized Metasploitable 2 scan with NVD disabled, (2) a second authorized scan with NVD enabled, each with its own raw JSON report and HTML dashboard rendered from that exact report, and (3) a clearly labeled synthetic JSON/dashboard fixture demonstrating per-host CVE deduplication, cross-service correlation, and mixed applicability evidence. The NVD-enabled report distinguishes version matches from unverified candidates and documents why neither alone proves exploitability. The synthetic fixture is fabricated test data, not a real scan or vulnerability.

## Tests

The test suite is designed to run without scanning a live target or making live NVD requests:

```bash
python -m unittest discover -s tests -v
```

## Output and privacy

Reports use a versioned JSON envelope:

- `schema_version`: report format version.
- `metadata`: requested target, Nmap-resolved hosts, selected ports/arguments, UTC timestamps, duration, scanner version, and one `host_os_fingerprints` record per resolved host (including hosts with no open TCP services).
- `summary`: host, open-service, raw CVE-observation, unique per-host CVE, cross-service CVE, Searchsploit-reference, network-exposure, risk-scored service, and remediation-guidance counts. Includes per-host CVE evidence grouped by identifier with every observed service/port, product/version, applicability states, and CVSS values; mixed service-level applicability is retained rather than flattened into a host-wide claim. The host priority is the highest valid service review-priority score, not a host compromise probability.
- `findings`: one record per discovered open TCP service, including evidence and assessment limitations.
- Each finding's `host_os_fingerprint`: per-service copy of the host-level Nmap OS match for convenient service-level review. The HTML report uses the host-level metadata as its source of truth, falls back to per-service records for older reports, and never treats Nmap accuracy as a probability.
- Each finding's `identification_evidence.technology_fingerprint` stores observed Nmap metadata and technology hints with their evidence source.
- `http_assessment` stores the optional HTTP response metadata and header/cookie hardening observations, or `not_requested` when the option is disabled.
- `web_intelligence` stores CMS/library hints and summary counts from the optional bounded HTML, robots, and sitemap inspection, or `not_requested` when disabled.
- `network_exposure` lists sensitive open-service observations, their evidence, severity, and remediation guidance.
- `exploit_intelligence` contains the integrated local Searchsploit references with official EDB links, explicit CVE-title correlations, platform/type metadata, validation guidance, and an always-explicit `not_executed` status.
- `risk_assessment` separates technical review priority from CVSS and includes an optional operator-contextual score.
- `remediation_guidance` contains service/CVE guidance and verification steps in `guidance_only` mode; no changes are executed.

Reports may contain target addresses, port/service information, software versions, and vulnerability references. Keep reports private unless you have checked them for sensitive information. Generated reports are excluded from version control by default; the explicitly reviewed, bounded lab sample under `evidence/` is intentionally tracked as portfolio evidence.

## Limitations

- Service identification depends on Nmap's detection and the information exposed by the target.
- NVD search results are candidates, not confirmed vulnerabilities.
- Version comparison is not guaranteed to model every vendor-specific version scheme. Ambiguous distro/build suffixes are intentionally left unverified because they may encode security backports; constrained CPE attributes not identified by the service scan are also left unverified.
- The scanner has a conservative evaluator for common NVD configuration-tree logic, but it only knows the detected service inventory. Multi-component requirements may therefore remain `candidate_unverified` until the full host inventory is available.
- Searchsploit classification is title/token based and may miss relevant results or retain imperfect matches. Exploit intelligence correlates CVEs only when an explicit CVE identifier appears in a title, structured source field, or duplicate observation; absence of a link does not mean the exploit is unrelated. EDB references are not proof of applicability, and ReconForge does not download or execute exploit code.
- The HTTP assessment checks only a single HEAD response from `/`; it does not crawl pages, inspect JavaScript, test forms, or validate application behavior.
- Web technology labels are heuristic, based on visible metadata and asset URL patterns; versions can be missing or spoofed. The scanner does not download JavaScript, crawl the application, or verify technology runtime state.
- Known-port exposure rules are heuristic. Services may use non-standard ports, and a port number does not conclusively identify the running service.
- Technical and contextual priority scores are transparent review heuristics, not CVSS or quantified business-loss estimates. Asset criticality and exposure are operator-supplied labels.
- Remediation guidance is advisory only and must be checked against vendor documentation and change-control procedures.
- The scanner does not exploit vulnerabilities or apply remediation and should not be used as a substitute for a professional security assessment.

## Responsible use

Use this tool only on systems you own or have explicit authorization to test. Follow applicable laws, rules of engagement, and the target owner's policies. The author is not responsible for misuse or damage caused by use of this software.

## License

Released under the MIT License. See [LICENSE](LICENSE).
