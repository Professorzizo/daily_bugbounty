import subprocess, os, requests, re, jsbeautifier, random
from datetime import datetime

# === إعدادات Telegram ===
TELEGRAM_BOT_TOKEN = "7525046599:AAECQzvF9UbK05-sTlXSXaZCUPzAcjKtbAM"
TELEGRAM_CHAT_ID = "5188067171"

# === ملفات التحكم ===
BASE_PATH = "/home/steel8566"
TARGETS_FILE = f"{BASE_PATH}/targets.txt"
USED_FILE = f"{BASE_PATH}/used_targets.txt"
RESULTS_PATH = f"{BASE_PATH}/results"
DATE = datetime.now().strftime('%Y-%m-%d')
TODAY_DIR = f"{RESULTS_PATH}/{DATE}"
os.makedirs(TODAY_DIR, exist_ok=True)

# === إرسال رسالة للتليجرام ===
def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message})

# === إرسال ملف للتليجرام ===
def send_telegram_file(file_path, caption=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    with open(file_path, 'rb') as f:
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "caption": caption if caption else ""}, files={"document": f})

# === تنفيذ أوامر النظام ===
def run_cmd(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
    return result.stdout.decode().strip()

# === تحديث قائمة أهداف HackerOne ===
def update_hackerone_targets():
    print("🛰️ Fetching HackerOne Programs...")
    url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/hackerone_data.json"
    try:
        response = requests.get(url)
        data = response.json()
    except:
        print("❌ Failed to fetch HackerOne data")
        return

    domains = set()
    for item in data:
        for scope in item.get("targets", {}).get("in_scope", []):
            if scope.get("asset_type") == "URL":
                domain = scope["asset_identifier"].replace("https://", "").replace("http://", "").split("/")[0]
                if "." in domain:
                    domains.add(domain.strip())

    old_domains = set()
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, "r") as f:
            old_domains = {line.strip() for line in f if line.strip()}

    all_domains = sorted(domains.union(old_domains))

    with open(TARGETS_FILE, "w") as f:
        f.write("\n".join(all_domains))

    print(f"✅ Updated targets.txt with {len(domains)} new domains (Total: {len(all_domains)})")

# === اختيار نطاقات جديدة للفحص ===
def pick_new_targets(count=3):
    if not os.path.exists(TARGETS_FILE):
        update_hackerone_targets()

    all_targets = [line.strip() for line in open(TARGETS_FILE) if line.strip()]
    used = [line.strip() for line in open(USED_FILE)] if os.path.exists(USED_FILE) else []

    remaining = [t for t in all_targets if t not in used]
    if len(remaining) < count:
        update_hackerone_targets()
        remaining = [line.strip() for line in open(TARGETS_FILE)]

    targets = random.sample(remaining, min(count, len(remaining)))

    with open(USED_FILE, "a") as uf:
        for t in targets:
            uf.write(t + "\n")

    return targets

# === فحص نطاق واحد ===
def analyze_target(domain):
    print(f"🔍 Analyzing: {domain}")
    dir_path = f"{TODAY_DIR}/{domain}"
    os.makedirs(dir_path, exist_ok=True)

    # === Subdomains ===
    subs = run_cmd(f"subfinder -d {domain} -silent; amass enum -passive -d {domain}")
    subs_file = f"{dir_path}/subs.txt"
    with open(subs_file, "w") as f: f.write(subs)

    if not subs.strip():
        msg = f"⚠️ No subdomains found for {domain}"
        print(msg)
        send_telegram_message(msg)
        return

    # === Live Hosts ===
    live_subs = run_cmd(f"echo '{subs}' | dnsx -silent")
    live_file = f"{dir_path}/live_subs.txt"
    with open(live_file, "w") as f: f.write(live_subs)

    # === URLs ===
    urls = run_cmd(f"(echo '{domain}' | gau; echo '{domain}' | waybackurls; katana -u {domain} -silent)")
    urls_file = f"{dir_path}/urls.txt"
    with open(urls_file, "w") as f: f.write(urls)

    # === JS Files ===
    js_files = "\n".join([u for u in urls.splitlines() if ".js" in u])
    js_file = f"{dir_path}/js.txt"
    with open(js_file, "w") as f: f.write(js_files)

    # === GF patterns ===
    xss_file = f"{dir_path}/xss.txt"
    run_cmd(f"echo '{urls}' | gf xss > {xss_file}")

    # === Dalfox XSS Scan ===
    dalfox_file = f"{dir_path}/dalfox.txt"
    dalfox_out = run_cmd(f"dalfox file {xss_file} --silence --no-spinner")
    with open(dalfox_file, "w") as f: f.write(dalfox_out)

    # === Nuclei Scan ===
    nuclei_file = f"{dir_path}/nuclei.txt"
    nuclei_out = run_cmd(f"nuclei -l {live_file} -silent -severity low,medium,high,critical")
    with open(nuclei_file, "w") as f: f.write(nuclei_out)

    # === Summary Stats ===
    stats = {
        "subs": len(subs.splitlines()),
        "live": len(live_subs.splitlines()),
        "urls": len(urls.splitlines()),
        "js_files": len(js_files.splitlines()),
        "xss": len(open(xss_file).readlines()),
        "dalfox_pocs": dalfox_out.count("POC:"),
        "nuclei": len(nuclei_out.splitlines())
    }

    summary = f"""✅ [BugBounty - {domain}]
🔸 Subdomains: {stats['subs']}
🔸 Live Hosts: {stats['live']}
🔸 URLs: {stats['urls']}
🔸 JS Files: {stats['js_files']}
🔸 XSS Params: {stats['xss']}
🔸 Dalfox POCs: {stats['dalfox_pocs']}
🔸 Nuclei Findings: {stats['nuclei']}"""

    print(summary)
    send_telegram_message(summary)

    # === إرسال الملفات على تليجرام ===
    send_telegram_file(subs_file, f"{domain} - Subdomains")
    send_telegram_file(live_file, f"{domain} - Live Hosts")
    send_telegram_file(urls_file, f"{domain} - URLs")
    send_telegram_file(js_file, f"{domain} - JS Files")
    send_telegram_file(dalfox_file, f"{domain} - Dalfox Results")
    send_telegram_file(nuclei_file, f"{domain} - Nuclei Scan")

# === Main ===
def main():
    update_hackerone_targets()
    targets = pick_new_targets(3)
    for t in targets:
        analyze_target(t)
    send_telegram_message(f"✅ Daily BugBounty Scan Finished ({DATE})")

if __name__ == "__main__":
    main()
