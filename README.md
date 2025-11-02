# OSINT Recon Tool

A simple Python tool for OSINT reconnaissance: gathers public info on IPs/domains using APIs and stores in SQLite for analysis. Ethical use only for learning purposes in cybersecurity.

## Installation
1. Clone the repository: `git clone https://github.com/6215642-design/osint_recon_tool.git`
2. Install dependencies: `pip install -r requirements.txt`

## Usage
- For IP: `python main.py --ip 8.8.8.8`
- For Domain: `python main.py --domain google.com`

Example output for IP:

Data is saved to `osint_data.db`. Query it with SQL, e.g., `SELECT * FROM recon_data;`.

## Ethics
This tool is for educational purposes only. Use on public data; do not violate privacy laws.

## License
MIT License
