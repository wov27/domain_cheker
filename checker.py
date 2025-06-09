"""
This module contains the core logic for finding, checking, and verifying domains.
It includes functions to scrape domains from expireddomains.net, check their availability
via WHOIS, and verify their safety using the VirusTotal API.
"""
import requests
from bs4 import BeautifulSoup
import time
import whois
from datetime import datetime, timedelta, timezone

# --- Constants ---
VT_API_V3_BASE_URL = "https://www.virustotal.com/api/v3"

# --- Logic Functions ---

def get_expired_domains(url, cookies):
    """
    Fetches a list of recently expired or deleted domains from a given expireddomains.net URL.

    Args:
        url (str): The URL from expireddomains.net with the desired filters applied.
        cookies (dict): A dictionary of cookies required for authentication.

    Returns:
        list: A list of domain names (str). Returns an empty list if fetching fails.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url, headers=headers, cookies=cookies, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml')
        domain_table = soup.find('table', class_='base1')
        if not domain_table:
            return []
        domain_list = [cell.a.text for row in domain_table.find('tbody').find_all('tr') if (cell := row.find('td')) and cell.a]
        return domain_list
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch page from expireddomains.net. Error: {e}")
        return []

def check_domains_availability(domains):
    """
    Checks the availability of a list of domains using WHOIS lookups.

    A domain is considered available if the WHOIS query returns no creation date
    or if a PywhoisError is raised (often indicating the domain does not exist).

    Args:
        domains (list): A list of domain names (str) to check.

    Returns:
        list: A list of domain names (str) that are considered available.
    """
    available_domains = []
    for domain in domains:
        time.sleep(1)
        try:
            w = whois.whois(domain)
            if not w.creation_date:
                available_domains.append(domain)
        except whois.parser.PywhoisError:
            available_domains.append(domain)
        except Exception as e:
            print(f"Error checking WHOIS for {domain}: {e}")
    return available_domains

def reanalyze_domains_vt_v3(domains, api_key, update_status_callback=None):
    """
    Requests a re-analysis of domains on VirusTotal, but only if the last
    analysis is older than one day.

    This function first fetches the current report for each domain. If the report
    is fresh (less than a day old), it's skipped. Otherwise, a new scan is triggered.
    It respects VirusTotal's public API rate limits by sleeping between requests.

    Args:
        domains (list): A list of domain names (str) to re-analyze.
        api_key (str): The VirusTotal API key.
        update_status_callback (function, optional): A callback function to update
            the status on the frontend. Defaults to None.
    """
    if not api_key:
        return
    headers = {"x-apikey": api_key}
    one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)

    for i, domain in enumerate(domains):
        should_rescan = True
        if update_status_callback:
            update_status_callback(f"Checking report age for: {domain} ({i+1}/{len(domains)})")
        
        get_url = f"{VT_API_V3_BASE_URL}/domains/{domain}"
        
        try:
            response = requests.get(get_url, headers=headers)
            time.sleep(16)

            if response.status_code == 200:
                report = response.json()
                last_analysis_timestamp = report.get('data', {}).get('attributes', {}).get('last_analysis_date')
                
                if last_analysis_timestamp:
                    last_analysis_date = datetime.fromtimestamp(last_analysis_timestamp, tz=timezone.utc)
                    if last_analysis_date > one_day_ago:
                        should_rescan = False
            
            elif response.status_code != 404:
                print(f"Error getting report for {domain}: Status {response.status_code}")
                # Don't try to rescan if we couldn't get a report for a reason other than not found
                should_rescan = False
            
            # Now, based on the flag, perform the rescan
            if should_rescan:
                if update_status_callback:
                    update_status_callback(f"Report is old/missing, requesting re-scan for {domain}...")
                post_url = f"{VT_API_V3_BASE_URL}/domains/{domain}/analyse"
                requests.post(post_url, headers=headers)
                time.sleep(16)
            else:
                if update_status_callback:
                    update_status_callback(f"Report for {domain} is fresh, skipping re-scan.")

        except requests.exceptions.RequestException as e:
            print(f"Network error during re-analysis check for {domain}: {e}")

def get_clean_domains_vt_v3(domains, api_key, target_counts, update_status_callback=None):
    """
    Retrieves reports for domains from VirusTotal and filters for "clean" ones.

    A domain is considered "clean" if its latest analysis report shows 0 malicious
    and no more than 1 suspicious flag. Domains not found on VirusTotal (404)
    are also considered clean. The function stops once the target number of domains
    for each TLD is met.

    Args:
        domains (list): A list of domain names (str) to check.
        api_key (str): The VirusTotal API key.
        target_counts (dict): A dictionary mapping TLDs (str) to the desired
            number of domains (int) for that TLD.
        update_status_callback (function, optional): A callback function to update
            the status on the frontend. Defaults to None.

    Returns:
        list: A list of "clean" domain names (str).
    """
    if not api_key:
        return domains
    headers = {"x-apikey": api_key}
    clean_domains = []
    collected_counts = {tld: 0 for tld in target_counts.keys()}
    for i, domain in enumerate(domains):
        if sum(collected_counts.values()) >= sum(target_counts.values()):
            break
        tld = domain.split('.')[-1]
        if tld in target_counts and collected_counts.get(tld, 0) >= target_counts[tld]:
            continue
        if update_status_callback:
            update_status_callback(f"Final check for: {domain} ({i+1}/{len(domains)})")
        url = f"{VT_API_V3_BASE_URL}/domains/{domain}"
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                report = response.json()
                stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                if malicious == 0 and suspicious <= 1:
                    clean_domains.append(domain)
                    if tld in collected_counts: collected_counts[tld] += 1
            elif response.status_code == 404:
                clean_domains.append(domain)
                if tld in collected_counts: collected_counts[tld] += 1
        except requests.exceptions.RequestException as e:
            print(f"Network error getting report for {domain}: {e}")
        time.sleep(16)
    return clean_domains 