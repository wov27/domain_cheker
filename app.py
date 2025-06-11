"""
The main Flask application file for the Domain Checker.

This application provides a simple web interface to start, stop, and monitor a
long-running domain checking task. The task is executed in a background thread
to keep the UI responsive. The application's state (e.g., progress, results)
is stored in a global dictionary, which is suitable for a single-user,
single-worker deployment model. For production environments with multiple workers,
a more robust shared state manager like Redis would be necessary.
"""
import threading
import time
import os
import configparser
import io
import csv
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
import checker
from checker import TaskStoppedException

app = Flask(__name__)

# --- In-memory State Management ---
# Using a lock is crucial for multi-threaded access to the shared task_state.
task_lock = threading.Lock()
task_state = {
    "status": "idle",  # "idle", "running", "stopping", "done", "error"
    "progress_message": "Готов к работе.",
    "results": [],
    "target_count": 0,
    "max_workers": 5,
    "expired_domains_url": "", 
    "current_domain_index": 0,
    "total_domains": 0,
    "domains_in_progress": {}, # {'domain.com': 'status message'}
    "stats": {"clean": 0}
}

# This class acts as a thread-safe proxy to the global `task_state`.
# All checker threads will use an instance of this to report progress.
class StatusManager:
    def __init__(self, state_dict, lock):
        self._state = state_dict
        self._lock = lock

    def reset(self, target_count, max_workers, custom_url):
        with self._lock:
            self._state.update({
                "status": "running", "progress_message": "Инициализация...",
                "results": [], "stats": {"clean": 0}, "target_count": target_count,
                "max_workers": max_workers,
                "expired_domains_url": custom_url or "Using config value",
                "current_domain_index": 0,
                "total_domains": 0,
                "domains_in_progress": {}
            })

    def is_stopping(self):
        with self._lock:
            return self._state['status'] == 'stopping'

    def set_total_domains(self, total):
        with self._lock:
            self._state['total_domains'] = total

    def set_progress_message(self, message):
        with self._lock:
            if self._state['status'] == 'running':
                self._state['progress_message'] = message

    def update_domain_status(self, domain, message):
        with self._lock:
            self._state['domains_in_progress'][domain] = message
            
    def remove_domain_from_progress(self, domain):
        with self._lock:
            if domain in self._state['domains_in_progress']:
                del self._state['domains_in_progress'][domain]
            self._state['current_domain_index'] += 1

    def add_clean_domain(self, domain_name, vt_link):
        with self._lock:
            if self._state['status'] in ['stopping', 'done']:
                return False

            if len(self._state['results']) < self._state['target_count']:
                self._state['results'].append({'domain': domain_name, 'vt_link': vt_link})
                self._state['stats']['clean'] += 1
                if len(self._state['results']) >= self._state['target_count']:
                    self._state['status'] = 'done'
                    self._state['progress_message'] = f"Задача выполнена. Найдено {len(self._state['results'])} доменов."
                    return False  # Stop other threads
            return True

    def get_found_count(self):
        with self._lock:
            return len(self._state['results'])

    def set_status(self, status, message=None):
        with self._lock:
            self._state['status'] = status
            if message:
                self._state['progress_message'] = message

# A single global instance of the manager
status_manager = StatusManager(task_state, task_lock)

def run_checker_task(target_domain_count, max_workers, custom_url):
    """
    The main worker function that runs the domain checking process in parallel.
    """
    status_manager.reset(target_domain_count, max_workers, custom_url)

    try:
        # Determine URL: use custom_url if provided, else fallback to config/env
        final_url = custom_url
        if not final_url:
            if os.getenv('EXPIRED_DOMAINS_URL'):
                final_url = os.getenv('EXPIRED_DOMAINS_URL')
            else:
                config = configparser.ConfigParser()
                config.read('config.ini')
                final_url = config.get('VARS', 'EXPIRED_DOMAINS_URL', fallback=None)

        if os.getenv('VIRUSTOTAL_API_KEY'):
            cfg_get = os.environ.get
            api_key = cfg_get('VIRUSTOTAL_API_KEY')
            session_cookies = {"ExpiredDomainssessid": cfg_get('SESSION_ID'), "reme": cfg_get('REME_COOKIE')}
        else:
            config = configparser.ConfigParser()
            config.read('config.ini')
            cfg = config['VARS']
            api_key = cfg.get('VIRUSTOTAL_API_KEY')
            session_cookies = {"ExpiredDomainssessid": cfg.get('SESSION_ID'), "reme": cfg.get('REME_COOKIE')}

        if not all([final_url, session_cookies["ExpiredDomainssessid"], session_cookies["reme"]]):
             raise Exception("Конфигурация не заполнена. Проверьте URL и cookies.")

        # This is now a blocking call that performs the entire parallel check.
        checker.run_parallel_check(
            url=final_url,
            cookies=session_cookies,
            vt_api_key=api_key,
            target_domain_count=target_domain_count,
            max_workers=max_workers,
            status_manager=status_manager
        )

        if status_manager.is_stopping():
            status_manager.set_status('idle', 'Проверка остановлена пользователем.')
        else:
            found_count = status_manager.get_found_count()
            status_manager.set_status('done', f'Задача выполнена. Найдено {found_count} доменов.')

    except TaskStoppedException:
        status_manager.set_status('idle', 'Проверка остановлена пользователем.')
    except Exception as e:
        print(f"Критическая ошибка в фоновой задаче: {e}")
        status_manager.set_status("error", f"Критическая ошибка: {e}")

@app.route('/')
def index():
    """Renders the main page of the application (index.html)."""
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run_task():
    """
    Starts the background domain checking task.
    
    It retrieves the desired number of domains from the form, ensures no other
    task is running, and then starts `run_checker_task` in a new thread.
    """
    if task_state['status'] == 'running':
        return redirect(url_for('index'))
        
    try:
        target_count = int(request.form.get('domain_count', 15))
        max_workers = int(request.form.get('max_workers', 5))
    except (ValueError, TypeError):
        target_count = 15
        max_workers = 5
    
    custom_url = request.form.get('expired_domains_url') or None
    
    # We set the status to 'running' under the lock via the manager
    # but the thread starts right after, so it's a minimal race condition.
    status_manager.set_status('running', 'Запуск потоков...')
    
    thread = threading.Thread(target=run_checker_task, args=(target_count, max_workers, custom_url))
    thread.start()
    
    return redirect(url_for('index'))

@app.route('/status')
def status():
    """
    Provides the current status of the background task as JSON.

    This endpoint is polled by the frontend JavaScript to dynamically update the UI
    with the latest progress messages, results, and overall application state.
    """
    with task_lock:
        return jsonify(task_state)

@app.route('/stop', methods=['POST'])
def stop_task():
    """
    Requests a stop for the currently running task.
    
    It sets the status to 'stopping', which is detected by the `check_stop_flag`
    callback inside the generator, causing a `TaskStoppedException` to be raised.
    """
    status_manager.set_status('stopping', 'Получен запрос на остановку...')
    return jsonify({"message": "Stop request received."})

@app.route('/export_csv')
def export_csv():
    """
    Generates and serves a CSV file of the found clean domains.
    """
    with task_lock:
        results = task_state.get("results", [])
        if not results:
            return redirect(url_for('index'))

        # Use io.StringIO to create the CSV in memory
        output = io.StringIO()
        # The field names must match the keys in the results dictionaries
        fieldnames = ['domain', 'vt_link']
        writer = csv.DictWriter(output, fieldnames=fieldnames)

        # Write header and data rows
        writer.writerow({'domain': 'Domain', 'vt_link': 'VirusTotal Report URL'})
        writer.writerows(results)

        # Create a Flask response object
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=results.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

if __name__ == '__main__':
    # For local development, run the app with Flask's built-in server in debug mode.
    # For production, it's recommended to use a WSGI server like Gunicorn.
    app.run(debug=True, host='0.0.0.0', port=5001) 