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

        # --- Stage 1: Scrape domains ---
        task_state["progress_message"] = "Step 1/5: Scraping domains from expireddomains.net..."
        scraped_domains = checker.get_expired_domains(expired_domains_url, session_cookies)
        task_state["stats"]["scraped"] = len(scraped_domains)
        if not scraped_domains:
            raise Exception("Failed to scrape any domains.")
        
        # --- Stage 2: Check WHOIS ---
        task_state["progress_message"] = "Step 2/5: Checking domain availability via WHOIS..."
        available_domains = checker.check_domains_availability(scraped_domains)
        task_state["stats"]["available"] = len(available_domains)
        if not available_domains:
            raise Exception("No available domains found after WHOIS check.")
            
        # --- Stage 3: Request Re-analysis ---
        checker.reanalyze_domains_vt_v3(available_domains, api_key, lambda msg: task_state.update({"progress_message": f"Step 3/5: {msg}"}))
        
        # --- Stage 4: Wait ---
        wait_minutes = 3
        for i in range(wait_minutes * 60, 0, -1):
            task_state["progress_message"] = f"Step 4/5: Waiting for VirusTotal to re-scan... Time left: {i//60}m {i%60}s"
            time.sleep(1)
            
        # --- Stage 5: Final Check ---
        target_counts = {'info': target_domain_count//3, 'top': target_domain_count//3, 'xyz': target_domain_count - 2*(target_domain_count//3)}
        final_domains = checker.get_clean_domains_vt_v3(available_domains, api_key, target_counts, lambda msg: task_state.update({"progress_message": f"Step 5/5: {msg}"}))
        task_state["stats"]["clean"] = len(final_domains)

        task_state["results"] = final_domains
        task_state["status"] = "done"
        task_state["progress_message"] = "All steps completed successfully!"

    except Exception as e:
        task_state["status"] = "error"
        task_state["progress_message"] = f"An error occurred: {e}"

@app.route('/')
def index():
    """Renders the main page of the application."""
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run_task():
    """
    Starts the domain checking task in a background thread.

    It's triggered by a POST request from the main page. It resets the task state,
    creates and starts a new daemon thread to run the `run_checker_task` function,
    and then redirects back to the main page. If a task is already running,
    it does nothing.
    """
    global task_state
    if task_state["status"] == "running":
        return redirect(url_for('index'))

    target_count = int(request.form.get('domain_count', 15))
    
    task_state = {
        "status": "running", 
        "progress_message": "Task starting...", 
        "results": [],
        "stats": {"scraped": 0, "available": 0, "clean": 0}
    }
    
    thread = threading.Thread(target=run_checker_task, args=(target_count,))
    thread.daemon = True
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

if __name__ == '__main__':
    # It's recommended to run Flask apps using a production server like Gunicorn,
    # but this is fine for local use.
    app.run(debug=True, host='0.0.0.0', port=5001) 