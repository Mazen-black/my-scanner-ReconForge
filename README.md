# my-scanner

A Python-based network service scanner that combines Nmap service/version detection with CVE lookups from the NVD and optional local Exploit-DB searches through Searchsploit. Results are saved as structured JSON for review.

> **Status:** Educational / portfolio project. Findings are leads for manual validation, not proof that a system is vulnerable.

## Features

- Uses Nmap for port scanning and service/version detection.
- Queries the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) for potentially relevant CVEs.
- Compares detected product/version information with available CPE and version-range data where possible.
- Optionally searches the local Exploit-DB database with `searchsploit`.
- Produces JSON output with service details, matching evidence, and assessment limitations.
- Includes offline unit and integration tests for CPE conversion, version applicability, result classification, and report structure.

## How it works

1. Nmap identifies open ports and service/version details on the specified target.
2. The scanner builds product/CPE-based queries and retrieves candidate CVE records from NVD.
3. Available CPE criteria and version bounds are compared with the detected version.
4. If Searchsploit is installed and enabled, local exploit references are searched and heuristically classified.
5. A JSON report is written for further review.

CVE matching and Searchsploit relevance classification are best-effort heuristics. Vendor version schemes, incomplete banners, CPE aliases, and complex NVD configuration logic can lead to false positives or false negatives. Always validate results against vendor advisories and the actual target.

## Requirements

- Python 3.10+
- Nmap installed and available on `PATH`
- Python packages listed in `requirements.txt`
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

```bash
git clone <REPOSITORY_URL>
cd my-scanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If you do not use Searchsploit, omit the `exploitdb` system package and run with `--no-exploitdb`.

## Usage

Only scan systems you own or have explicit permission to assess.

Basic scan:

```bash
python scanner.py --target 192.0.2.10
```

Specify ports and an output file:

```bash
python scanner.py --target 192.0.2.10 --ports 1-1000 --output report.json
```

Disable the local Exploit-DB search:

```bash
python scanner.py --target 192.0.2.10 --no-exploitdb
```

Provide an NVD API key through an environment variable (recommended over putting a key in shell history):

```bash
export NVD_API_KEY="YOUR_NVD_API_KEY"
python scanner.py --target 192.0.2.10
```

You can also pass `--nvd-api-key`, but avoid saving secrets in scripts, screenshots, shell history, or reports. Get an API key from the official [NVD API site](https://nvd.nist.gov/developers/request-an-api-key).

View all options:

```bash
python scanner.py --help
```

Replace `192.0.2.10` with a lab target or another system you are authorized to scan. The address above is reserved for documentation examples.

## Tests

The test suite is designed to run without scanning a live target or making live NVD requests:

```bash
python -m unittest discover -s tests -v
```

## Output and privacy

Reports may contain target addresses, port/service information, software versions, and vulnerability references. Keep reports private unless you have checked them for sensitive information. Generated scan reports are intentionally excluded from version control by `.gitignore`.

## Limitations

- Service identification depends on Nmap's detection and the information exposed by the target.
- NVD search results are candidates, not confirmed vulnerabilities.
- Version comparison is not guaranteed to model every vendor-specific version scheme.
- NVD configuration trees can contain complex logical relationships; the current assessment should be treated as an indicator, not a complete implementation of the NVD applicability specification.
- Searchsploit classification is title/token based and may miss relevant results or retain imperfect matches.
- The scanner does not exploit vulnerabilities and should not be used as a substitute for a professional security assessment.

## Responsible use

Use this tool only on systems you own or have explicit authorization to test. Follow applicable laws, rules of engagement, and the target owner's policies. The author is not responsible for misuse or damage caused by use of this software.

## License

This project is intended to be released under the MIT License. See [LICENSE](LICENSE).
