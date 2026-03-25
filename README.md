# SARA — Simple Automated Recon App

Self-hosted recon automation web app for bug bounty and penetration testing. Runs reconnaissance tools sequentially on a single target domain, streams results in real-time to the browser, and exports findings as PDF or CSV.

## Features

- **Automated subdomain enumeration** with subfinder
- **Web probing & technology detection** via httpx
- **Directory and file fuzzing** with ffuf
- **Conditional vulnerability scanning** using nuclei (only if technologies detected)
- **Real-time output streaming** to browser via Server-Sent Events (SSE)
- **Export results** as PDF or CSV
- **Scan history** and past result retrieval
- **Low-resource design** optimized for 512MB VPS deployments

## Requirements

Before running SARA, ensure the following are installed on your system:

- Python 3.10+
- Go 1.18+ (for installing Go-based tools)
- subfinder
- httpx
- ffuf
- nuclei
- pip (Python package manager)

The exact pip dependencies are listed in `requirements.txt` and will be installed in the setup steps below.

## Local Setup

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd sara
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Go-based tools**
   ```bash
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install -v github.com/projectdiscovery/ffuf@latest
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings (port, wordlist path, etc.)
   ```

5. **Run the application**
   ```bash
   uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```

Open http://localhost:8000 in your browser.

## VPS Setup (Debian)

Deploy SARA to a Debian VPS (e.g., 1 core, 512MB RAM) with the following steps:

1. **Update system packages**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Python and Go**
   ```bash
   sudo apt install -y python3.10 python3-pip golang-go git curl
   ```

3. **Install Go-based tools**
   ```bash
   export PATH=$PATH:$(go env GOPATH)/bin
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install -v github.com/projectdiscovery/ffuf@latest
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   ```

4. **Clone and configure SARA**
   ```bash
   git clone <repo-url> /opt/sara
   cd /opt/sara
   pip install -r requirements.txt
   cp .env.example .env
   # Edit .env as needed
   ```

5. **Configure Nginx reverse proxy**

   Install Nginx:
   ```bash
   sudo apt install -y nginx
   ```

   Create `/etc/nginx/sites-available/sara`:
   ```nginx
   upstream sara_backend {
       server 127.0.0.1:8000;
   }

   server {
       listen 80;
       server_name your-domain.com;

       # Optional: redirect to HTTPS
       # return 301 https://$server_name$request_uri;

       location / {
           proxy_pass http://sara_backend;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

   Enable the site:
   ```bash
   sudo ln -s /etc/nginx/sites-available/sara /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

6. **Run SARA as a systemd service**

   Create `/etc/systemd/system/sara.service`:
   ```ini
   [Unit]
   Description=SARA Recon App
   After=network.target

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/opt/sara
   ExecStart=/usr/bin/python3 -m uvicorn main:app --host 127.0.0.1 --port 8000
   Restart=on-failure
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

   Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable sara
   sudo systemctl start sara
   ```

7. **Optional: Add basic authentication**

   Install apache2-utils for htpasswd:
   ```bash
   sudo apt install -y apache2-utils
   sudo htpasswd -c /etc/nginx/.htpasswd admin
   ```

   Add to the location block in your Nginx config:
   ```nginx
   auth_basic "SARA Access";
   auth_basic_user_file /etc/nginx/.htpasswd;
   ```

   Restart Nginx:
   ```bash
   sudo systemctl restart nginx
   ```

## Usage

1. **Open SARA in your browser**
   ```
   http://localhost:8000
   ```

2. **Enter a target domain**
   - Type the domain name in the input field (e.g., `example.com`)
   - Click the **SCAN** button

3. **Monitor real-time output**
   - Watch the terminal output panel as the scan pipeline executes
   - Status panel shows progress through each recon tool

4. **Export results**
   - Once the scan completes, use the **PDF** or **CSV** buttons to export findings

5. **Review scan history**
   - Toggle the **HISTORY** section to view past scans
   - Click **View** to reload previous results

## Disclaimer

SARA is designed for **authorized security testing only**. Always obtain explicit written permission from the target organization before scanning their assets. Unauthorized scanning may be illegal in your jurisdiction. The authors assume no liability for misuse.

## Security Notes

- Domain inputs are validated with regex to prevent command injection before passing to subprocesses.
- The FastAPI server binds to `127.0.0.1` by default. Use Nginx as a reverse proxy for public access.
- No authentication is built into the app. Add basic auth at the Nginx level if exposed to the internet.
- All tools run sequentially with a 30-minute timeout per scan to protect against resource exhaustion.
- Only one scan executes at a time; additional requests are queued.
