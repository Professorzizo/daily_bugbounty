# 🕵️ BugBounty Daily Automation

This repository automates **Bug Bounty Recon & Scanning** every day and generates HTML reports that are hosted on **GitHub Pages**.

---

## ✅ What it does

- Fetches fresh **HackerOne program scopes** daily
- Picks **3 new targets per day** automatically
- Performs:
  - **Subdomain enumeration** (`subfinder + amass`)
  - **Live host discovery** (`dnsx`)
  - **URL crawling** (`gau + waybackurls + katana`)
  - **JS file collection & secret analysis**
  - **XSS parameter extraction** (`gf`)
  - **Dalfox XSS scanning**
  - **Nuclei vulnerability scanning**
- Generates **HTML report per target**
- Generates **daily index.html** listing all domains scanned that day
- Updates a **main index.html** linking all days
- Pushes everything to **GitHub Pages**
- Sends **Telegram notifications** with summary stats

---

## ✅ Requirements

Install these tools before running:

```bash
sudo apt update && sudo apt install -y git python3-pip golang

# Recon tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v3/...@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python dependencies
pip3 install jsbeautifier requests rich


✅ Setup


  git clone https://github.com/Professorzizo/daily_bugbounty.git


------------------------------------------------------------------------------
#Configure Telegram bot
  Edit daily_bugbounty.py:

  TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN"
  TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"

------------------------------------------------------------------------------
#RUN:

python3 daily_bugbounty.py


✅ Daily Automation (cron)

crontab -e

0 3 * * * /usr/bin/python3 bugbounty-reports/daily_bugbounty.py >> /home/USER/dailylog.txt 2>&1

