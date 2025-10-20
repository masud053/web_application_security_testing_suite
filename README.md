# web_application_security_testing_suite

## Overview
This project is a **fully automated web security assessment pipeline** designed for both professional penetration testers and security learners. It integrates **Nmap**, **Nikto**, and **FFUF** scans into a structured workflow, automatically generating detailed reports (in text, JSON, and PDF formats) and visual dashboards using **Streamlit**.

The toolkit simplifies scanning, parsing, and analyzing results from multiple tools, classifies vulnerabilities by severity, and provides actionable remediation advice.



## Features
✅ Automated scanning with Nmap, Nikto, and FFUF  
✅ Intelligent parsing of open ports, services, and vulnerabilities  
✅ Severity classification (High, Medium, Low)  
✅ Fix suggestions for detected vulnerabilities  
✅ One-click tool installation via `install_tools.sh`   
✅ Streamlit dashboard for interactive visualization  
✅ Modular & extensible architecture  


## Installation

### Clone the repository
```bash
git clone https://github.com/<yourusername>/auto-webscan.git
cd auto-webscan
```

### Install dependencies
```bash
chmod +x install_tools.sh
./install_tools.sh
```

### Give scan scripts execute permission
```bash
chmod +x scan_pipeline.sh
```


## Usage

### Run full scan
```bash
./scan_pipeline.sh <TARGET_URL>
```
Example:
```bash
./scan_pipeline.sh http://dvwa.local
```

### Generate report
```bash
python3 generate_report.py
```

### Launch dashboard
```bash
streamlit run streamlit_dashboard.py
```


## Recommended Tools
- **Nmap** → Network and service discovery  
- **Nikto** → Web vulnerability scanning  
- **FFUF** → Directory and file fuzzing  
- **xmlstarlet**, **jq**, **awk**, **grep** → Data parsing utilities  
- **Python 3 (reportlab, pandas)** → Report generation  
- **Streamlit** → Dashboard visualization  


## Example Dashboard Preview
The dashboard presents:
- Scan statistics
- Vulnerability classification
- Port and service summaries
- Fix recommendations

**Developed by:** Masud rana  
**Field:** Cybersecurity & Ethical Hacking  
**Focus:** Automated Vulnerability Assessment and Reporting Systems


## Contribute
Contributions are welcome! Fork the repository, submit a pull request, or report issues.

