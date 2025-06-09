"""
This is the main Flask application file.

It provides a web interface to trigger and monitor the domain checking process.
The main logic is run in a background thread to avoid blocking the web server.
State is managed in a simple global dictionary, suitable for a single-worker setup.
"""
import threading
import time
import os
import configparser
from flask import Flask, render_template, request, jsonify, redirect, url_for
import checker

app = Flask(__name__)

# A custom exception to signal a user-requested stop
class TaskStoppedException(Exception):
    pass

# --- In-memory state management ---
# This is a simple way to handle state for a single-worker server.
# For multi-worker setups, a more robust solution like Redis would be needed.
task_state = {
    "status": "idle",  # "idle", "running", "done", "error"
    "progress_message": "",
    "results": [],
    "stats": {
        "scraped": 0,
        "available": 0,
        "clean": 0
    }
}

def update_and_check_stop(message):
    """A wrapper for updating status that also checks if a stop is requested."""
    if task_state['status'] == 'stopping':
        raise TaskStoppedException("Task stopped by user.")
    task_state['progress_message'] = message

def run_checker_task(target_domain_count):
    """
    The main worker function that executes the domain checking pipeline in a background thread.

    This function orchestrates the entire process:
    1. Reads configuration from config.ini.
    2. Scrapes domains from expireddomains.net.
    3. Checks domain availability via WHOIS.
    4. Triggers a re-analysis on VirusTotal.
    5. Waits for the analysis to complete.
    6. Fetches the final reports and filters for clean domains.

    It updates the global `task_state` dictionary to reflect its progress, which is
    then served to the frontend via the /status endpoint.

    Args:
        target_domain_count (int): The total number of clean domains the user wants to find.
    """
    global task_state
    
    try:
        # --- Reset state and read config ---
        task_state.update({
            "status": "running", 
            "progress_message": "Step 1/5: Starting...",
            "results": [],
            "stats": {"scraped": 0, "available": 0, "clean": 0}
        })
        
        # --- Read config ---
        # Prioritize environment variables for production (e.g., on Render)
        # Fall back to config.ini for local development
        if os.getenv('VIRUSTOTAL_API_KEY'):
            expired_domains_url = os.getenv('EXPIRED_DOMAINS_URL')
            api_key = os.getenv('VIRUSTOTAL_API_KEY')
            session_cookies = {
                "ExpiredDomainssessid": os.getenv('SESSION_ID'),
                "reme": os.getenv('REME_COOKIE')
            }
        else:
            config = configparser.ConfigParser()
            config.read('config.ini')
            cfg = config['VARS']
            
            expired_domains_url = cfg['EXPIRED_DOMAINS_URL']
            api_key = cfg['VIRUSTOTAL_API_KEY']
            session_cookies = {
                "ExpiredDomainssessid": cfg['SESSION_ID'],
                "reme": cfg['REME_COOKIE']
            }

        if not all([expired_domains_url, api_key, session_cookies["ExpiredDomainssessid"], session_cookies["reme"]]) or \
           'YOUR_' in api_key or 'YOUR_' in session_cookies["ExpiredDomainssessid"]:
             raise Exception("Configuration is missing or incomplete. Please set environment variables or fill in config.ini.")

        # --- Stage 1: Get Expired Domains ---
        update_and_check_stop("Step 1/5: Scraping domains from expireddomains.net...")
        scraped_domains = checker.get_expired_domains(expired_domains_url, session_cookies)
        task_state["stats"]["scraped"] = len(scraped_domains)
        if not scraped_domains:
            task_state["progress_message"] = "Could not find any domains with the specified filters."
            task_state["status"] = "done"
            return
        
        # --- Stage 2: Check Availability (WHOIS) ---
        available_domains = checker.check_domains_availability(scraped_domains, update_status_callback=update_and_check_stop)
        task_state["stats"]["available"] = len(available_domains)
        if not available_domains:
            raise Exception("No available domains found after WHOIS check.")
            
        # --- Stage 3: Request Re-analysis ---
        checker.reanalyze_domains_vt_v3(available_domains, api_key, update_status_callback=update_and_check_stop)
        
        # --- Stage 4: Wait ---
        wait_minutes = 3
        for i in range(wait_minutes * 60, 0, -1):
            update_and_check_stop(f"Step 4/5: Waiting for VirusTotal to re-scan... Time left: {i//60}m {i%60}s")
            time.sleep(1)
            
        # --- Stage 5: Final Check ---
        update_and_check_stop("Step 5/5: Getting final reports from VirusTotal...")
        clean_domains = checker.get_clean_domains_vt_v3(available_domains, api_key, update_status_callback=update_and_check_stop)
        task_state["stats"]["clean"] = len(clean_domains)

        # Limit the results to the number requested by the user
        final_domains = clean_domains[:target_domain_count]

        task_state["results"] = final_domains
        task_state["status"] = "done"
        task_state["progress_message"] = "Process finished successfully."

    except TaskStoppedException:
        task_state["status"] = "idle"
        task_state["progress_message"] = "Task stopped by user."
    except Exception as e:
        task_state["status"] = "error"
        task_state["progress_message"] = f"An error occurred: {str(e)}"

@app.route('/')
def index():
    """Renders the main page of the application."""
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run_task():
    """Starts the background checker task."""
    target_count_str = request.form.get('domain_count', '15')
    try:
        target_count = int(target_count_str)
    except (ValueError, TypeError):
        target_count = 15

    global task_state
    if task_state['status'] == 'running':
        return redirect(url_for('index'))
    
    thread = threading.Thread(target=run_checker_task, args=(target_count,))
    thread.start()
    
    return redirect(url_for('index'))

@app.route('/status')
def status():
    """
    Provides the current status of the background task.

    This endpoint is polled by the frontend using JavaScript to update the UI
    with the latest progress message and results.

    Returns:
        JSON: A JSON object containing the current task state.
    """
    return jsonify(task_state)

@app.route('/stop', methods=['POST'])
def stop_task():
    """Endpoint to request a stop for the running task."""
    if task_state['status'] == 'running':
        task_state['status'] = 'stopping'
    return jsonify({"message": "Stop request received."})

if __name__ == '__main__':
    # It's recommended to run Flask apps using a production server like Gunicorn,
    # but this is fine for local use.
    app.run(debug=True, host='0.0.0.0', port=5001) 