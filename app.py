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
from flask import Flask, render_template, request, jsonify, redirect, url_for
import checker
from checker import TaskStoppedException

app = Flask(__name__)

# --- In-memory State Management ---
task_state = {
    "status": "idle",  # "idle", "running", "stopping", "done", "error"
    "progress_message": "Готов к работе.",
    "results": [],
    "target_count": 0,
    "stats": {"clean": 0}
}

def run_checker_task(target_domain_count):
    """
    The main worker function that runs the domain checking process.

    This function acts as a consumer for the `domain_check_generator` from the `checker` module.
    It initializes the application state, reads the necessary configuration, and then
    iterates over the generator. For each domain yielded by the generator, it updates
    the global `task_state`. It also handles exceptions, including user-initiated stops
    and other unexpected errors, ensuring the application state is always consistent.

    Args:
        target_domain_count (int): The number of clean domains the user wants to find.
    """
    global task_state

    task_state.update({
        "status": "running", "progress_message": "Инициализация...",
        "results": [], "stats": {"clean": 0}, "target_count": target_domain_count
    })

    def update_status_callback(message):
        task_state['progress_message'] = message

    def check_stop_flag():
        return task_state['status'] == 'stopping'

    try:
        if os.getenv('VIRUSTOTAL_API_KEY'):
            # Production environment (e.g., Render)
            cfg_get = os.environ.get
            expired_domains_url = cfg_get('EXPIRED_DOMAINS_URL')
            api_key = cfg_get('VIRUSTOTAL_API_KEY')
            session_cookies = {
                "ExpiredDomainssessid": cfg_get('SESSION_ID'), "reme": cfg_get('REME_COOKIE')
            }
        else:
            # Local development
            config = configparser.ConfigParser()
            config.read('config.ini')
            cfg = config['VARS']
            cfg_get = cfg.get
            expired_domains_url = cfg_get('EXPIRED_DOMAINS_URL')
            api_key = cfg_get('VIRUSTOTAL_API_KEY')
            session_cookies = {
                "ExpiredDomainssessid": cfg_get('SESSION_ID'), "reme": cfg_get('REME_COOKIE')
            }

        if not all([expired_domains_url, session_cookies["ExpiredDomainssessid"], session_cookies["reme"]]):
             raise Exception("Конфигурация не заполнена. Укажите URL и cookies в config.ini или переменных окружения.")

        domain_generator = checker.domain_check_generator(
            url=expired_domains_url, cookies=session_cookies, vt_api_key=api_key,
            target_domain_count=target_domain_count,
            update_status_callback=update_status_callback,
            check_stop_flag=check_stop_flag
        )

        clean_domains_found = []
        for domain in domain_generator:
            result_obj = {
                "name": domain,
                "vt_link": f"https://www.virustotal.com/gui/domain/{domain}"
            }
            clean_domains_found.append(result_obj)
            
            task_state["results"] = clean_domains_found
            task_state["stats"]["clean"] = len(clean_domains_found)
            update_status_callback(f"Найден чистый домен: {domain} ({len(clean_domains_found)}/{target_domain_count})")
            time.sleep(1)

        if task_state['status'] == 'running':
            task_state['status'] = 'done'

    except TaskStoppedException:
        task_state['status'] = 'idle'
        task_state['progress_message'] = 'Проверка остановлена пользователем.'

    except Exception as e:
        print(f"Критическая ошибка в фоновой задаче: {e}")
        task_state["status"] = "error"
        task_state["progress_message"] = f"Критическая ошибка: {e}"

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
    except (ValueError, TypeError):
        target_count = 15
    
    task_state['status'] = 'running'
    
    thread = threading.Thread(target=run_checker_task, args=(target_count,))
    thread.start()
    
    return redirect(url_for('index'))

@app.route('/status')
def status():
    """
    Provides the current status of the background task as JSON.

    This endpoint is polled by the frontend JavaScript to dynamically update the UI
    with the latest progress messages, results, and overall application state.
    """
    return jsonify(task_state)

@app.route('/stop', methods=['POST'])
def stop_task():
    """
    Requests a stop for the currently running task.
    
    It sets the status to 'stopping', which is detected by the `check_stop_flag`
    callback inside the generator, causing a `TaskStoppedException` to be raised.
    """
    if task_state['status'] == 'running':
        task_state['status'] = 'stopping'
    return jsonify({"message": "Stop request received."})

if __name__ == '__main__':
    # For local development, run the app with Flask's built-in server in debug mode.
    # For production, it's recommended to use a WSGI server like Gunicorn.
    app.run(debug=True, host='0.0.0.0', port=5001) 