# leakx

A small command‑line tool that creates a clean Excel report (`.xlsx`) from:

- LeakRadar CSV exports, or
- LeakRadar API searches (by domain or IP)

It also adds OSINT details (date compromised, computer name, OS, malware path) by looking up each username/email.

## Requirements

- Python 3.10+
- `requests`
- `openpyxl`

Install:

```bash
python3 -m pip install requests openpyxl
```

## Quick Use (most common)

### 1) Merge CSV files into one report

If you do not pass `-d/-dl/-i/-il`, the tool reads CSVs from `./files` (if it exists) or the current folder.

```bash
python3 leakx.py -o report.xlsx
```

### 2) Fetch by domain from LeakRadar API

```bash
python3 leakx.py -d example.com -o report.xlsx
```

### 3) Fetch by IP from LeakRadar API

```bash
python3 leakx.py -i 127.0.0.1 -o report.xlsx
```

## API Key

Put your LeakRadar API key in a text file (one line). Default path is `./keys.txt` next to `leakx.py`.

```bash
python3 leakx.py -d example.com --key /path/to/keys.txt -o report.xlsx
```

Tip: do not commit your key file.

## Options (simple list)

```
-ff, --folder      CSV folder (CSV mode)
-d,  --domain      Domain filter or API domain search
-dl, --domain-list Text file with one domain per line
-i,  --ip          API search by IP
-il, --ip-list     Text file with one IP per line
--tenant           Expand domains using Microsoft tenant discovery
--auto-unlock      Auto-unlock locked items (consumes points)
--key              API key file path (default: ./keys.txt)
-v,  --verbose     Print progress
-o,  --output      Output XLSX file (required)
```

Notes:

- IP search is API-only (cannot be used with CSV mode).
- Domain search and IP search cannot be combined.

## CSV Filename Rule (when filtering)

If you filter CSVs by domain, filenames must include the domain as the **second** underscore‑separated part:

```
anything_<domain>_<category>_anything.csv
```

Example:

```
leakradar_example.com_credentials_2024-01.csv
```

## Output

The Excel report includes (when available):

- `DOMAIN`, `CATEGORY`, `URL`, `USERNAME`, `PASSWORD`, `ADDED_AT`
- `IP` (only in IP mode)
- OSINT fields: `date_compromised`, `computer_name`, `operating_system`, `malware_path`

If multiple domains are included, each domain gets its own sheet. Otherwise it writes one sheet named `Leak Report`.

## Common Examples

Merge all CSVs in a folder:

```bash
python3 leakx.py -ff ./exports -o report.xlsx
```

Fetch multiple domains (one per line):

```bash
python3 leakx.py -dl domains.txt -o report.xlsx
```

Fetch multiple IPs:

```bash
python3 leakx.py -il ips.txt -o report.xlsx
```
