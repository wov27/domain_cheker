# Domain Checker

Инструмент для автоматического поиска и проверки доменных имен. Он получает списки недавно освободившихся доменов с [expireddomains.net](https://www.expireddomains.net/), проверяет их доступность через WHOIS и анализирует на вредоносное ПО с помощью VirusTotal API, используя эффективный последовательный подход.

## Основные возможности

- **Сбор доменов**: Автоматически загружает списки доменов с `expireddomains.net` по заданным вами фильтрам (URL необходимо настроить в конфиге).
- **Эффективная проверка**: Проверяет домены строго по одному. Если вам нужно найти 3 домена, работа остановится сразу после нахождения третьего, не тратя время на остальные.
- **Проверка доступности**: Использует WHOIS для определения, свободен ли домен для регистрации.
- **Анализ на VirusTotal**: Проверяет репутацию домена через VirusTotal API.
- **Умный повторный анализ**: Если отчет VirusTotal устарел (старше 1 дня), инструмент принудительно запускает новый анализ, чтобы получить самые актуальные данные.
- **Веб-интерфейс**: Удобный интерфейс на Flask для запуска, остановки и мониторинга процесса проверки в реальном времени.
- **Копирование результатов**: Позволяет скопировать список найденных чистых доменов в один клик.

## Требования

- Python 3.8+
- pip

## Установка

1.  **Клонируйте репозиторий:**
    ```bash
    git clone https://github.com/wov27/domain_cheker.git
    cd domain_cheker
    ```

2.  **Создайте и активируйте виртуальное окружение:**
    -   **macOS / Linux:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    -   **Windows:**
        ```bash
        python -m venv venv
        .\venv\Scripts\activate
        ```

3.  **Установите зависимости:**
    ```bash
    pip install -r requirements.txt
    ```

## Настройка

Перед первым запуском необходимо создать и настроить конфигурационный файл.

1.  **Создайте файл `config.ini`**, скопировав `config.ini.example`:
    ```bash
    cp config.ini.example config.ini
    ```

2.  **Откройте `config.ini` и вставьте ваши данные:**

    ```ini
    [VARS]
    # 1. URL с expireddomains.net
    # Зайдите на сайт, настройте фильтры (например, только .com, без цифр и дефисов)
    # и скопируйте сюда получившийся URL из адресной строки браузера.
    EXPIRED_DOMAINS_URL = "https://www.expireddomains.net/..."

    # 2. Ваш API-ключ от VirusTotal
    # Его можно найти в личном кабинете на сайте VirusTotal.
    VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

    # 3. Cookies для доступа к expireddomains.net
    # Нужны для аутентификации. Их нужно взять из вашего браузера после логина на сайте.
    # - Откройте инструменты разработчика (F12)
    # - Перейдите на вкладку "Application" (Chrome) или "Storage" (Firefox)
    # - Найдите раздел Cookies -> https://www.expireddomains.net
    # - Скопируйте значения для ключей "ExpiredDomainssessid" и "reme".
    # ВАЖНО: Если в значении cookie есть символ '%', его нужно удвоить (%%).
    SESSION_ID = "YOUR_SESSION_ID"
    REME_COOKIE = "YOUR_REME_COOKIE"
    ```

## Запуск

После установки и настройки запустите веб-приложение:

```bash
python app.py
```

Сервер будет доступен по адресу `http://127.0.0.1:5001`. Просто откройте эту ссылку в вашем браузере.

## Использование

1.  Откройте `http://127.0.0.1:5001` в браузере.
2.  Укажите желаемое количество доменов для поиска.
3.  Нажмите кнопку **"Начать проверку"**.
4.  Наблюдайте за процессом в блоке **"Статус"**.
5.  Найденные чистые и свободные домены будут появляться в блоке **"Результаты"** в виде кликабельных ссылок на отчет VirusTotal.
6.  Вы можете остановить проверку в любой момент кнопкой **"Стоп"**.
7.  Когда нужные домены найдены, скопируйте их список с помощью кнопки **"Скопировать все"**.

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