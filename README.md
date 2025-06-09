# Domain Checker

This is a web-based tool to automate the process of finding valuable expired domains. It scrapes domain lists from `expireddomains.net`, checks their availability using WHOIS, and verifies their safety through VirusTotal, including a mandatory re-scan for up-to-date results.

## Features

- **Web Interface**: A simple Flask-based UI to start and monitor the checking process.
- **Domain Scraping**: Fetches domain lists from `expireddomains.net` using your personal filters and session cookies.
- **Availability Check**: Uses `python-whois` to determine if domains are actually available for registration.
- **Robust VirusTotal Check**:
    - Leverages the VirusTotal API v3 to check for malicious content.
    - **Forces a re-analysis** for every domain to ensure the report is fresh.
    - Filters domains, allowing only those with 0 `malicious` and max 1 `suspicious` flags.
- **Configuration Management**: All sensitive data (API keys, cookies) is stored in a `config.ini` file, which is excluded from version control.

## How to Use

### 1. Prerequisites
- Python 3.9+
- Git

### 2. Setup
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/wov27/domain_cheker.git
    cd domain_cheker
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the application:**
    - Rename `config.ini.example` to `config.ini` (or create `config.ini` manually).
    - Open `config.ini` and fill in your details:
        - `EXPIRED_DOMAINS_URL`: The URL from `expireddomains.net` that has your desired filters applied.
        - `SESSION_ID`: Your `ExpiredDomainssessid` cookie value.
        - `REME_COOKIE`: Your `reme` cookie value.
        - `VIRUSTOTAL_API_KEY`: Your API key from VirusTotal.
    
    > **How to get cookies:**
    > 1. Log in to `expireddomains.net`.
    > 2. Open your browser's developer tools (F12).
    > 3. Go to the "Application" (or "Storage") tab.
    > 4. Find the cookies for the `expireddomains.net` domain and copy the values for `ExpiredDomainssessid` and `reme`.

### 3. Running the Application
1.  **Start the Flask server:**
    ```bash
    python app.py
    ```
    Or, if you have issues with the environment:
    ```bash
    venv/bin/python app.py
    ```

2.  **Open the web interface:**
    - Navigate to `http://127.0.0.1:5001` in your web browser.

3.  **Start the check:**
    - Enter the desired number of domains for each TLD you want to find.
    - Click the "Run Check" button.
    - The status will be updated in real-time on the page. The process is long, primarily due to the mandatory 20-minute wait for VirusTotal re-scans.

## Project Structure

```
.
├── app.py                # Main Flask application, handles web routes and background tasks.
├── checker.py            # Core logic for scraping, WHOIS, and VirusTotal checks.
├── config.ini            # Stores configuration and secrets (API keys, cookies). Not in Git.
├── requirements.txt      # Python package dependencies.
├── templates/
│   └── index.html        # HTML template for the web interface.
├── .gitignore            # Specifies files to be ignored by Git.
└── README.md             # This file.
``` 