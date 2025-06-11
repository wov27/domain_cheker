"""
This module contains the core logic for finding, checking, and verifying domains
in parallel.

The main entry point is `run_parallel_check`, which uses a thread pool to process
multiple domains concurrently. It relies on a thread-safe `StatusManager` instance,
passed from the Flask app, to report detailed, real-time progress for each domain
and to manage the overall task state (e.g., handling stop requests).
"""
import requests
from bs4 import BeautifulSoup
import time
import whois
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# A custom exception to signal a user-requested stop
class TaskStoppedException(Exception):
    """Custom exception raised when a task is stopped by the user."""
    pass

# --- Constants ---
VT_API_V3_BASE_URL = "https://www.virustotal.com/api/v3"

# --- Main Parallel Orchestration Function ---

def run_parallel_check(url, cookies, vt_api_key, target_domain_count, max_workers, status_manager):
    """
    Finds and checks domains in parallel.

    This function orchestrates the entire checking process. It fetches a list of
    domains, then uses a ThreadPoolExecutor to run checks for each domain
    concurrently. It stops once the target number of clean domains is found or
    all domains are processed.

    Args:
        url (str): The URL from expireddomains.net to scrape.
        cookies (dict): Authentication cookies for expireddomains.net.
        vt_api_key (str): The VirusTotal API key.
        target_domain_count (int): The number of clean domains to find.
        max_workers (int): The number of parallel threads to use.
        status_manager (StatusManager): The thread-safe manager for reporting status.
    """
    status_manager.set_progress_message("Этап 1/3: Получение списка доменов...")
    
    # Simple callback for get_expired_domains to report errors
    def error_callback(msg):
        status_manager.set_progress_message(msg)

    all_domains = get_expired_domains(url, cookies, error_callback)
    if not all_domains:
        status_manager.set_progress_message("Не удалось получить домены. Проверьте URL и cookies.")
        return

    status_manager.set_total_domains(len(all_domains))
    status_manager.set_progress_message(f"Найдено {len(all_domains)} доменов. Запуск {max_workers} потоков...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a future for each domain check
        future_to_domain = {
            executor.submit(
                _check_single_domain, domain, cookies, vt_api_key, status_manager
            ): domain for domain in all_domains
        }

        for future in as_completed(future_to_domain):
            if status_manager.is_stopping() or status_manager.get_found_count() >= target_domain_count:
                # Cancel pending futures
                for f in future_to_domain:
                    f.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                raise TaskStoppedException()

            domain = future_to_domain[future]
            try:
                is_clean = future.result()
                if is_clean:
                    # add_clean_domain is thread-safe and respects target_count
                    if status_manager.add_clean_domain(domain):
                        status_manager.set_progress_message(f"Найден чистый домен: {domain}")
                
            except Exception as e:
                status_manager.update_domain_status(domain, f"Ошибка: {e}")
            finally:
                # Clean up the in-progress list
                status_manager.remove_domain_from_progress(domain)


def _check_single_domain(domain, cookies, vt_api_key, status_manager):
    """
    Performs all checks for a single domain. Designed to be run in a thread.
    
    Args:
        domain (str): The domain to check.
        cookies (dict): Auth cookies.
        vt_api_key (str): VT API key.
        status_manager (StatusManager): The status manager instance.

    Returns:
        bool: True if the domain is clean and available, False otherwise.
    
    Raises:
        Exception: Propagates exceptions from checker functions.
    """
    if status_manager.is_stopping():
        raise TaskStoppedException()
        
    # 1. WHOIS Check
    status_manager.update_domain_status(domain, "Проверка WHOIS...")
    if not is_domain_available(domain, status_manager):
        status_manager.update_domain_status(domain, "Занят (WHOIS)")
        return False

    if status_manager.is_stopping():
        raise TaskStoppedException()

    # 2. VirusTotal Check
    status_manager.update_domain_status(domain, "Проверка VirusTotal...")
    is_clean, error_message = verify_domain_with_vt(domain, vt_api_key, status_manager)
    if error_message:
        raise Exception(error_message)
    
    if not is_clean:
        status_manager.update_domain_status(domain, "Не прошел проверку VT")
        return False
        
    status_manager.update_domain_status(domain, "Чистый и доступен!")
    return True


# --- Helper Functions (modified to accept status_manager) ---

def get_expired_domains(url, cookies, update_status):
    """
    Fetches domains from expireddomains.net.

    Args:
        url (str): The URL to scrape.
        cookies (dict): The authentication cookies.
        update_status (function): Callback to report errors.

    Returns:
        list: A list of domain names, or an empty list on failure.
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
        
        tbody = domain_table.find('tbody')
        if not tbody:
            return []

        domain_list = []
        for row in tbody.find_all('tr'):
            first_cell = row.find('td')
            if first_cell and first_cell.a:
                domain_list.append(first_cell.a.text)
        
        return domain_list
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Ошибка сети при доступе к expireddomains.net: {e}"
        print(error_msg)
        update_status(error_msg)
        return []

def is_domain_available(domain, status_manager):
    """
    Checks if a single domain is available via WHOIS.
    """
    # No need to report granular status here, _check_single_domain does it.
    try:
        time.sleep(1) # Keep sleep to avoid rate-limiting
        w = whois.whois(domain)
        return not w.status or not w.creation_date
    except whois.parser.PywhoisError:
        return True
    except Exception as e:
        # Propagate the error to be caught in the main loop
        raise Exception(f"WHOIS-ошибка: {e}")

def verify_domain_with_vt(domain, api_key, status_manager):
    """
    Performs a full, robust VirusTotal verification for a single domain.
    """
    def _is_report_clean(report):
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        return malicious == 0 and suspicious <= 1

    if not api_key or 'YOUR_' in api_key:
        return True, None # Default to "clean" if VT is not configured

    headers = {"x-apikey": api_key}
    get_url = f"{VT_API_V3_BASE_URL}/domains/{domain}"
    
    try:
        if status_manager.is_stopping(): raise TaskStoppedException()
        status_manager.update_domain_status(domain, "VT: запрос отчета...")
        time.sleep(16) # Adhere to public API rate limits
        response = requests.get(get_url, headers=headers, timeout=30)

        if response.status_code == 401:
            return False, "Ошибка аутентификации VirusTotal."
        
        needs_rescan = True
        if response.status_code == 200:
            report = response.json()
            last_analysis_ts = report.get('data', {}).get('attributes', {}).get('last_analysis_date')
            if last_analysis_ts:
                last_analysis_date = datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc)
                if last_analysis_date > (datetime.now(timezone.utc) - timedelta(days=1)):
                    status_manager.update_domain_status(domain, "VT: свежий отчет, проверка...")
                    needs_rescan = False
                    return _is_report_clean(report), None
        
        if needs_rescan:
            if status_manager.is_stopping(): raise TaskStoppedException()
            status_manager.update_domain_status(domain, "VT: запуск повторного анализа...")
            post_url = f"{VT_API_V3_BASE_URL}/domains/{domain}/analyse"
            time.sleep(16)
            rescan_response = requests.post(post_url, headers=headers, timeout=30)
            if rescan_response.status_code == 401:
                return False, "Ошибка аутентификации VirusTotal."

            status_manager.update_domain_status(domain, "VT: ожидание (90 сек)...")
            # Check for stop signal periodically while waiting
            for _ in range(30):
                if status_manager.is_stopping(): raise TaskStoppedException()
                time.sleep(3)
        
        if status_manager.is_stopping(): raise TaskStoppedException()
        status_manager.update_domain_status(domain, "VT: получение финального отчета...")
        time.sleep(16)
        final_response = requests.get(get_url, headers=headers, timeout=30)
        
        if final_response.status_code != 200:
            return False, f"Не удалось получить отчет (код: {final_response.status_code})."
            
        final_report = final_response.json()
        return _is_report_clean(final_report), None

    except requests.exceptions.RequestException as e:
        return False, f"Сетевая ошибка VT: {e}"
    except requests.exceptions.JSONDecodeError:
        return False, "Ошибка обработки ответа VT."
    except Exception as e:
        return False, f"Неожиданная ошибка VT: {e}"