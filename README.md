# IOC Enricher - SOC Triage Automation Tool 🛡️

Designed to simplify the work of SOC analysts, this lightweight Python tool automates initial threat filtering. It validates IPs and hashes, extracts information from VirusTotal and AbuseIPDB, and delivers ready-to-use reports in CSV and JSON formats.

## Features
- **Regex Validation & Auto-Classification:** Automatically detects IPv4 addresses and MD5, SHA1, and SHA256 hashes.
- **Threat Intelligence APIs:**
  - **AbuseIPDB:** Abuse confidence score, total reports, country, and ISP info.
  - **VirusTotal v3:** Engines detection ratio (malicious/suspicious/harmless) and sample status.
- **Rate-Limit Handling:** Controlled execution delays to respect public API quotas and avoid HTTP 429 errors.
- **Multi-Format Export:** Generates structured `.json` reports for SIEM ingestion and `.csv` files for quick analyst triage.

## Project Structure
```text
ioc-enricher/
├── .env.example
├── .gitignore
├── enricher.py
├── iocs.txt
├── requirements.txt
└── README.md
```

## Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Fernando-dev-cyber/ioc-enricher.git
   cd ioc-enricher
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On OS Windows:
   .\venv\Scripts\activate
   # On OS Linux/macOS:
   source venv/bin/activate
   ```

3. **install dependencies for the project :**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   Rename `.env.example` to `.env` and insert *your* API keys:
   ```env
   VT_API_KEY=your_virustotal_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   ```

## Usage

Prepare a text file (`iocs.txt`) containing the list of IOCs (one per line) and execute:

```bash
python enricher.py -f iocs.txt -o triage_report
```

### Parameters
- `-f, --file`: Path to the input file containing IOCs (Required).
- `-o, --output`: Base name for the generated `.csv` and `.json` reports (Default: `ioc_report`).

## Sample Output (CSV Preview)
| IOC | Tipo | Detalle Amenaza / Score | ISP / Proveedor | Error |
| :--- | :--- | :--- | :--- | :--- |
| `185.220.101.5` | IP | Score Abuso: 100% | Zwiebelfreunde e.V. | |
| `275a021b...fd0f` | SHA256 | Detecciones VT: 66 maliciosos / 0 sospechosos | N/A | |