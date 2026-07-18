# Microsoft Patch Tuesday Fetcher

This Python script fetches the latest Microsoft Patch Tuesday updates from Microsoft's Security Update API. It extracts the KB articles and CVEs, and displays them in a readable format.

![CI](https://github.com/EmmanuelTsouris/ms-patch-tuesday-fetcher/actions/workflows/ci.yml/badge.svg)

## Features

- Fetch Microsoft Patch Tuesday updates within a specified number of days.
- Extract and display KB articles and the products they apply to.
- Extract CVEs, with two levels of detail:
  - **Notable CVEs** (default) — the publicly disclosed / actively exploited CVEs highlighted in the release note, with no extra API calls.
  - **Full CVE detail** (`--full-cves`) — the complete per-CVE list from the MSRC CVRF API, including severity, CVSS base score, impact, exploitation status, and the affected products with their KBs.
- Filter results to a specific product (`--product`).
- Emit structured JSON (`--json`) for scripting or feeding to another tool.
- Option to show raw API output for debugging purposes.

## Prerequisites

- Python 3.10 or newer
- The following Python packages:
  - `requests`
  - `beautifulsoup4`

For instructions on deploying this script to AWS Lambda, see the [Lambda Setup Guide](./lambda_example/LAMBDA_SETUP.md).

## Setup

### Step 1: Create a virtual environment

You can create and activate a virtual environment for this project by running:

```bash
python -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Dependencies

Once the environment is activated, install the necessary dependencies:

```bash
pip install requests beautifulsoup4
```

### Step 3: Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/EmmanuelTsouris/ms-patch-tuesday-fetcher.git
cd ms-patch-tuesday-fetcher
```

### Step 4: Run the Script

You can run the script to fetch the latest Patch Tuesday updates for a default of the last 7 days:

```bash
python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py
```

#### Fetching Updates from the Last X Days

To fetch updates from the last X number of days, use the `--days` argument:

```bash
python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py --days 30
```

This will fetch updates from the last 30 days.

#### Fetching Full CVE Detail

By default the tool lists only the **notable** CVEs called out in the release note (no extra API calls). To fetch the complete per-CVE list — with severity, CVSS score, impact, exploitation status, and affected products/KBs — use `--full-cves`:

```bash
python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py --days 30 --full-cves
```

This makes one additional request per month to the MSRC CVRF API. If that request fails, the tool falls back to the notable-CVE subset.

#### Filtering by Product

Use `--product` to narrow the results to a product-name substring (case-insensitive). Combined with `--full-cves`, this is handy for answering "what did this month's updates fix on the machines I just patched?":

```bash
python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py --days 30 --full-cves --product "Windows Server 2025"
```

#### JSON Output

Use `--json` to emit the structured report instead of human-readable text — useful for scripting or handing the data to another tool (for example, an assistant drafting release notes after applying updates):

```bash
python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py --days 30 --full-cves --product "Windows Server 2025" --json
```

Each CVE object in full mode looks like:

```json
{
  "id": "CVE-2026-56155",
  "title": "Active Directory Federation Services Elevation of Privilege Vulnerability",
  "severity": "Important",
  "impact": "Elevation of Privilege",
  "cvss": 7.8,
  "exploited": true,
  "publicly_disclosed": false,
  "exploitation": "Exploitation Detected",
  "notable": true,
  "products": [
    { "product": "Windows Server 2025", "kb": "5099536" }
  ]
}
```

In the default (notable-only) mode, each CVE object carries just `id`, `title`, `exploitation`, and `notable`.

#### Show Raw API Output for Debugging

To see the raw API output for debugging purposes, use the `--raw` flag:

```bash
python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py --raw
```

You can also combine the `--raw` and `--days` arguments, for example:

```bash
python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py --days 30 --raw
```

## How It Works

- The script fetches Microsoft Patch Tuesday updates from the [Microsoft Security Update Guide API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API).
- It extracts KB articles and the products they apply to from the release-note summary.
- It extracts the **notable** CVEs (publicly disclosed / actively exploited) directly from the release note. With `--full-cves`, it additionally fetches each month's CVRF document for the complete per-CVE detail.
- The script can also print the raw API response for debugging using the `--raw` flag.

## Example Output

```bash
Found 1 updates from the last 7 days.
- Title: July 2026 Security Updates, Released on: 2026-07-14T07:00:00-07:00
  KB Articles:
  - KB5002882 (Applies to: SharePoint Server Subscription Edition)
  - KB5099536 (Applies to: Windows Server 2025)
  CVEs (4):
  - CVE-2026-50661 - Windows BitLocker Security Feature Bypass Vulnerability (Publicly Known)
  - CVE-2026-56155 - Active Directory Federation Services Elevation of Privilege Vulnerability (Exploitation Detected)
  - CVE-2026-56164 - Microsoft SharePoint Server Elevation of Privilege Vulnerability (Exploitation Detected)
  - CVE-2026-58644 - Microsoft SharePoint Remote Code Execution Vulnerability (Exploitation Detected)
```

## Testing

Unit tests are deterministic and mock the network:

```bash
pytest
```

Live integration tests (excluded from the default run) exercise the real MSRC API:

```bash
pytest -m integration
```

## Contributing

If you'd like to contribute to this project, feel free to fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
