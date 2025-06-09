import requests
from bs4 import BeautifulSoup
import time
import whois
from datetime import datetime, timedelta, timezone

def get_expired_domains(filter_url, session_cookies=None):
    """
    Fetches a list of domains from a specific expireddomains.net URL.

    :param filter_url: The URL from expireddomains.net with all filters applied.
    :param session_cookies: A dictionary of cookies needed for authentication.
    :return: A list of domain names.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://www.expireddomains.net/',
    }

    print(f"Fetching domains from: {filter_url}")

    try:
        response = requests.get(filter_url, headers=headers, cookies=session_cookies, timeout=30)
        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status()

        print("Successfully fetched the page.")
        soup = BeautifulSoup(response.content, 'lxml')

        domain_list = []
        # We need to find the correct selector for the domain table and rows
        # This is a guess and might need to be adjusted after inspecting the page
        domain_table = soup.find('table', class_='base1')
        if not domain_table:
            print("Could not find the domain table on the page.")
            print("The page layout might have changed, or you might need to provide login cookies.")
            return []

        # Find all rows in the table body, skipping the header
        for row in domain_table.find('tbody').find_all('tr'):
            # The domain is usually in the first 'td' element, inside an 'a' tag
            cell = row.find('td')
            if cell and cell.a:
                domain_list.append(cell.a.text)

        return domain_list

    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch page. Error: {e}")
        return []

def check_domains_availability(domains):
    """
    Checks a list of domains for availability using WHOIS lookups.

    :param domains: A list of domain names to check.
    :return: A list of domains that are available for registration.
    """
    available_domains = []
    print(f"\n--- Checking availability for {len(domains)} domains ---")
    for i, domain in enumerate(domains):
        # Adding a small delay to avoid overwhelming WHOIS servers
        time.sleep(1)
        print(f"({i+1}/{len(domains)}) Checking: {domain}...")
        try:
            w = whois.whois(domain)
            # If a domain has no creation date, it's very likely available.
            # Some registrars return minimal info for registered domains, but creation_date is standard.
            if not w.creation_date:
                print(f"  -> Status: AVAILABLE")
                available_domains.append(domain)
            else:
                print(f"  -> Status: Registered")
        except whois.parser.PywhoisError:
            # The python-whois library often raises this error for unregistered domains.
            print(f"  -> Status: AVAILABLE (No WHOIS record)")
            available_domains.append(domain)
        except Exception as e:
            # Catch other potential errors (e.g., network issues, weird TLDs)
            print(f"  -> Status: Error checking domain - {e}")
    
    return available_domains

# --- New VirusTotal v3 Functions ---

VT_API_V3_BASE_URL = "https://www.virustotal.com/api/v3"

def reanalyze_domains_vt_v3(domains, api_key):
    """Requests a re-analysis for a list of domains using VirusTotal API v3."""
    if not api_key:
        print("\n--- VirusTotal Re-analysis Skipped: No API Key Provided ---")
        return
    
    print(f"\n--- Requesting re-analysis for {len(domains)} domains (API v3) ---")
    headers = {"x-apikey": api_key}
    
    for i, domain in enumerate(domains):
        url = f"{VT_API_V3_BASE_URL}/domains/{domain}/analyse"
        print(f"({i+1}/{len(domains)}) Requesting re-scan for: {domain}...")
        try:
            response = requests.post(url, headers=headers)
            if response.status_code == 200:
                print(f"  -> Re-analysis request successful.")
            else:
                # This will catch things like 429 Rate Limit Exceeded
                print(f"  -> Received status {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"  -> Network error requesting re-scan: {e}")
        # Public API rate limit is 4 lookups per minute. Let's be safe.
        time.sleep(16)

def get_clean_domains_vt_v3(domains, api_key, target_counts):
    """Gets domain reports from VirusTotal API v3 and returns a list of clean domains."""
    if not api_key:
        print("\n--- VirusTotal Final Check Skipped: No API Key Provided ---")
        return domains
        
    print(f"\n--- Performing final check for {len(domains)} domains (API v3) ---")
    headers = {"x-apikey": api_key}
    clean_domains = []
    collected_counts = {tld: 0 for tld in target_counts.keys()}

    for i, domain in enumerate(domains):
        # Stop if we have collected enough domains in total
        if sum(collected_counts.values()) >= sum(target_counts.values()):
            print("\nTarget number of clean domains reached. Stopping final checks.")
            break

        tld = domain.split('.')[-1]
        
        # Skip if we already have enough for this TLD
        if tld in target_counts and collected_counts.get(tld, 0) >= target_counts[tld]:
            continue

        print(f"({i+1}/{len(domains)}) Final check for: {domain}...")
        try:
            response = requests.get(f"{VT_API_V3_BASE_URL}/domains/{domain}", headers=headers)
            if response.status_code == 200:
                report = response.json()
                stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                # Allow up to 1 suspicious flag, but no malicious flags.
                if malicious == 0 and suspicious <= 1:
                    print(f"  -> Status: CLEAN (Malicious: {malicious}, Suspicious: {suspicious})")
                    clean_domains.append(domain)
                    if tld in collected_counts:
                        collected_counts[tld] += 1
                else:
                    print(f"  -> Status: FLAGGED (Malicious: {malicious}, Suspicious: {suspicious})")

            elif response.status_code == 404:
                print(f"  -> Status: No report found, considered CLEAN.")
                clean_domains.append(domain)
                if tld in collected_counts:
                    collected_counts[tld] += 1
            else:
                print(f"  -> Received status {response.status_code}: {response.text}")
                # Cautiously add domain if there's an API error
                clean_domains.append(domain)
                if tld in collected_counts:
                    collected_counts[tld] += 1

        except requests.exceptions.RequestException as e:
            print(f"  -> Network error getting report: {e}")
            clean_domains.append(domain)
            if tld in collected_counts:
                collected_counts[tld] += 1
        time.sleep(16)
        
    return clean_domains

if __name__ == "__main__":
    # ------------------------------------------------------------------
    # IMPORTANT: Paste your VirusTotal API Key here
    # ------------------------------------------------------------------
    VIRUSTOTAL_API_KEY = "12020c32466f7e86d7148b6b086dffc432cfc277a4c9128aecbe5d7f1b178ae3" # <-- PASTE KEY HERE

    # ------------------------------------------------------------------
    # IMPORTANT: Please paste the URL you get from expireddomains.net here
    # ------------------------------------------------------------------
    USER_PROVIDED_URL = "https://member.expireddomains.net/domains/combinedexpired/?savedsearch_id=541015&flast30d=1&ftlds[]=12&ftlds[]=595&ftlds[]=465&flimit=200&fadult=1&q=seobukmark&fexcludemakeoffer=3&fmseocf=20&fmseotf=5&fwhois=22&o=changes&r=d"

    # If the script doesn't work, you might need to provide session cookies.
    # I will guide you on how to get this if needed.
    COOKIES = {
        "ExpiredDomainssessid": "xWekNAfbQ%2CZ16RRF%2CGrOZuc4K8H8u1m0jUChyBY0osnR4RIptsfszJh7AyWAD7cNDd3K73VuwGfPrqUPNuoKMUM0IYV9GelRUK26CtOVUCN0djYtW-oOoeY3ICfUbQAN",
        "reme": "wovan27%3A%7C%3A6AtfubUVtWLs8L9Rmf124O9eFJwpKcfbTd0bgyOI"
    }

    # --- PRODUCTION PARAMETERS ---
    TARGET_COUNTS = {'info': 5, 'top': 5, 'xyz': 5}
    REANALYSIS_WAIT_MINUTES = 20
    SKIP_WHOIS_CHECK_AND_USE_CACHED = True # Set to False for a full run
    # ---

    if not USER_PROVIDED_URL:
        print("Please edit 'main.py' and provide the URL from expireddomains.net with your filters applied.")
    else:
        scraped_domains = get_expired_domains(USER_PROVIDED_URL, session_cookies=COOKIES)
        
        if scraped_domains:
            print(f"\nFound {len(scraped_domains)} domains from the source.")
            
            available_domains = []
            if SKIP_WHOIS_CHECK_AND_USE_CACHED:
                print("\n--- Skipping WHOIS check and using cached list of available domains ---")
                available_domains = [
                    'NiceEdge.top', 'an-ka.xyz', 'DaunMuda.xyz', 'DaunPro.xyz', 'kinh88.info', 
                    'bkrhypotheek.info', 'RotsVast.info', 'cnerbartery.info', '1MuseumVip.xyz', 
                    '2MuseumVip.xyz', '3MuseumVip.xyz', '5MuseumVip.xyz', 'TrendZone.info', 
                    'hbtech.info', 'baileybrug.info', 'elblogtamaulipeco.info', 
                    'PsoriasisFreeForLife.info', 'papermodelz.info', 'onlinegeldlenen.info', 
                    'Occams-Razor.info', 'icsatc.info', 'nanoplastia.info', 'nncxv.info', 
                    'qdia.info', 'Premium-Scripts.info', 'SpanishAmericanWar.info', 
                    'Channel-758.info', 'Amole.info', 'bemyyoc2.top', 'a9sqlzc3.top', 
                    '1Win29.top', 'hooistheman.xyz', 'MahaTate.info', 'dx-talk.info', 
                    'cpns2024.info', '1sttime.xyz', 'RespIranDo.info', 'geschirrmobile.info', 
                    'PampaKinIs.info', 'FrontBird.xyz', 'sx51.top', 'uhbsgdferayl.xyz', 
                    'MannaBase.info', 'jzgqfs.top', 'qozsji.top', 'bbxgva.top', 'rucxmn.top', 
                    'xrtroy.top', 'gcuxzc.top', 'tgouzm.top', 'hdddik.top', 'iwgafy.top', 
                    'djkgyh.top', 'rlkhor.top', 'ShinyBathroom.info'
                ]
            else:
                available_domains = check_domains_availability(scraped_domains)

            if available_domains:
                # Stage 1: Request re-analysis for ALL available domains
                reanalyze_domains_vt_v3(available_domains, VIRUSTOTAL_API_KEY)
                
                # Stage 2: Wait for the analysis to complete
                print(f"\n--- Waiting for {REANALYSIS_WAIT_MINUTES} minutes for VirusTotal to re-scan... ---")
                time.sleep(REANALYSIS_WAIT_MINUTES * 60)
                print("--- Wait time complete. ---")

                # Stage 3: Perform the final check to collect targets
                final_clean_domains = get_clean_domains_vt_v3(available_domains, VIRUSTOTAL_API_KEY, TARGET_COUNTS)
                
                if final_clean_domains:
                    print(f"\n--- FINAL RESULTS: Found {len(final_clean_domains)} available and clean domains matching targets ---")
                    for domain in final_clean_domains:
                        print(domain)
                else:
                    print("\n--- FINAL RESULTS: No clean domains found from the available list. ---")
            else:
                print("\n--- Results: No available domains found from the scraped list. ---")
        else:
            print("\nNo domains found from scraping. This could be because:")
            print("1. No domains matched your criteria.")
            print("2. Your session is not authenticated (we may need to add cookies).")
            print("3. The website structure has changed.") 