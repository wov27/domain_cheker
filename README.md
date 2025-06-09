# Domain Checker and Acquirer

This project is a Python script that automates the process of finding, checking, and acquiring expired domain names.

## Features

- Scrapes expired domains from `expireddomains.net` based on specified filters.
- Checks domain availability and pricing using the Namecheap API.
- Verifies domains for malware using the VirusTotal API.
- Re-analyzes domains on VirusTotal if the last scan is outdated.
- Provides a list of clean and available domains.
- Buys selected domains via the Namecheap API.
- Allows updating DNS servers for newly purchased domains. 