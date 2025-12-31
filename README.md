# SSH Brute-Force Log Analyzer (Python)

## Project Overview
This project is a security automation tool designed to parse Linux authentication logs (`auth.log`), identify suspicious behavior, and detect **SSH Brute-Force attacks**. It automates the task of a Junior SOC Analyst by filtering noise and highlighting high-risk IP addresses based on a customizable threshold.

##  Key Features
- **Log Parsing:** Uses Regular Expressions (Regex) to extract IP addresses from failed login attempts.
- **Threat Detection:** Aggregates failed attempts and flags IPs that exceed a security threshold (e.g., more than 5 failed attempts).
- **API Integration:** Ready for enrichment via external threat intelligence APIs (e.g., AbuseIPDB) to check the reputation of the attacker's IP.
- **Reporting:** Generates a clear security report in the terminal for incident response.


##  Project Structure
- `analyzer.py`: The main Python engine that processes logs.
- `auth.log`: A sample log file containing simulated SSH attack patterns.
- `requirements.txt`: List of Python dependencies.

## How to Run
1. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/log-sentinel-python.git](https://github.com/yourusername/log-sentinel-python.git)
2. Navigate to the folder:
   ```bash
    cd log-sentinel-python
3. Run the analyzer:
  ```bash
  python3 analyzer.py
