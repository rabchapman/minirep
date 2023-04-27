# minirep
This repository is used for the ISP-452 Threat Intelligence Lab. Your goal for this module will be to extend the functionality of the tool to incorporate additional services. 

We will also use this project during our network analysis module to automate blocking of suspicious or malicious IP addresses.

Examples of services with free API access tiers are below (pick one or two, and feel free to find others not listed here):
* GreyNoise (https://docs.greynoise.io/docs/using-the-greynoise-community-api)
* Shodan (https://developer.shodan.io/api/requirements)
* Abuse IPDB (https://www.abuseipdb.com/api.html)
* ARIN (https://www.arin.net/resources/registry/whois/rws/api/)
* SecurityTrails (https://docs.securitytrails.com/docs/overview)
* Proofpoint Emerging Threats (https://rules.emergingthreats.net/)
* Threat Jammer (https://threatjammer.com/docs/threat-jammer-api-keys)
* IP GeoLocation API (https://ipgeolocation.io/)

# Prerequisites
1. Python 3.8+
2. VirusTotal API Key
3. Create a fork of the minirep repository

# Installation (Windows)
1. Launch PowerShell
2. Clone the repository: `git clone <URL of your forked repository>`
3. Change directories into the repository folder: `cd minirep`
4. Create the virtual environment: `python -m venv .`
5. Activate the virtual environment: `.\Scripts\activate`
6. Install the required packages: `pip3 install -r requirements.txt`
7. Create the config file (update the command with your API key from VT): 
```PowerShell
@{"vt_api_key"="YOUR_API_KEY_HERE";"vt_api_url"="https://www.virustotal.com/api/v3"} | ConvertTo-Json | Out-File .\minirep.json`
```
8. Run minirep.py: `python3 minirep.py`

# Installation (Linux)
1. Install python3-virtualenv (this is dependent on the OS you are running): `sudo apt install python3.10-venv`
2. Clone the repository: `git clone <URL of your forked repository>`
3. Change directories into the repository folder: `cd minirep`
4. Create the virtual environment: `python -m venv .`
5. Activate the virtual environment: `source ./bin/activate`
6. Install the required packages: `pip3 install -r requirements.txt`
7. Create the minirep.json config file: `vi minirep.json`
```json
{
    "vt_api_url":  "https://www.virustotal.com/api/v3",
    "vt_api_key":  "YOUR_API_KEY_HERE",
    "splunk_host": "192.168.0.1",
    "splunk_port": 8089,
    "splunk_user": "isp452",
    "splunk_pass": "******"
}
```
8. Run minirep.py: `python3 minirep.py` OR to query Splunk for IPs, run `python3 minirep.py -q`

# Analysis
Based on the data you gather, render a verdict of either `DENY`, `ALERT`, `PASS`. 
* Denied IPs should be blocked from ingress/egress on your network. 
* Alerting IPs should be monitored for further activity. These will be subject to further inspection for a definitive verdict
* Passed IPs will be ignored

# Outcomes
- Interact with API services
- Understand IP reputation services and how they can assist with making decisions to protect your network
- Understand the limitations of these services (e.g. true & false positives, transience of IPs, etc.)