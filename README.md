🎪 JSJungleGym.sh

"Where JavaScript goes to get naked, and secrets forget to hide."

---

## 👋 What Is This Thing?

Imagine you're a digital archaeologist, but instead of digging for bones, you're crawling websites for:
- 🔐 Hardcoded passwords that developers *swear* they didn't leave there
- 📦 Outdated libraries with more CVEs than a virus convention
- 🕵️ Suspicious API keys chilling in plain sight

**JSJungleGym** is your automated buddy that:
1. 🕷️ Crawls a website and sniffs out every `.js` file (like a bloodhound with a caffeine problem)
2. 📥 Downloads them all with verbose curl love (`-vv` for the nerds)
3. 🐍 Scans for credentials & library versions using regex wizardry
4. 🔍 Runs **Horusec** for static analysis (because machines spot what humans miss)
5. 🐳 Fires up **Snyk** in Docker to find vulnerable dependencies
6. 📊 Spits out tidy `.txt` reports so you don't have to play "find the needle in the haystack"



 🚀 Quick Start (For the Impatient)

```bash
# 1. Grab the script
chmod +x JSJungleGym.sh

# 2. Point it at a target (that you own or have permission to test, please 🙏)
./JSJungleGym.sh https://target.com

# 3. For React/Vue/Angular SPAs that load JS dynamically:
./JSJungleGym.sh --spa https://app.target.com

# 4. Want Snyk to actually work well? Add your token:
export SNYK_TOKEN=your_token_here
./JSJungleGym.sh https://target.com

# 5. Check the loot:
ls jsjungle_workspace/reports/
```

---

##  What You Get

```
jsjungle_workspace/
└── reports/
    ├── first_step_link_finder.txt  # All the JS URLs we found
    ├── raw_js_responses.txt        # curl -vv verbosity (headers + bodies)
    ├── python_analysis.txt         # 🔐 Credentials & 🏷️ Library versions
    ├── horufind.txt                # Horusec SAST findings
    └── snyk_vulns.txt              # Snyk dependency vulnerability report
```

---

##  Modes

| Flag | What It Does | When to Use |
|------|-------------|-------------|
| *(none)* | Fast regex-based extraction | Static sites, simple JS, quick scans |
| `--spa` | Playwright headless browser mode | React/Vue/Angular apps that lazy-load JS like it's going out of style |
| `--help` | Shows this fancy README in your terminal | When you forget everything (we've all been there) |

---

##  Requirements 

```bash
# You'll need these installed:
curl          # For downloading JS like a polite robot
python3       # For the regex magic
horusec       # For static analysis (install: https://docs.horusec.io)
docker        # For Snyk in a clean container
nodejs + npm  # Only if using --spa mode (for Playwright)
```

---

## 🎯 Example Output Snippets

```text
[CREDENTIAL] app.min.js: api_key: "sk_live_abc123xyz789"
[VERSION] jquery v1.2.3
[VERSION] lodash v4.17.15

[+] Found 42 JavaScript endpoints
[+] Downloaded 38 JS files (4 failed - probably CORS being dramatic)
[+] 🔍 Found 7 potential findings (creds/versions)
```



## 🐛 Troubleshooting (Because Tech)

| Problem | Likely Cause | Quick Fix |
|---------|-------------|-----------|
| `0 JavaScript endpoints` | Target blocks bots / SPA / wrong URL | Try `--spa` mode or check URL format (`https://` not `https//:`) |
| `SSL certificate error` | Self-signed cert on localhost | Use `http://` for local testing, or add cert to trust store |
| `Snyk scan failed` | No token / no package.json / network issues | `export SNYK_TOKEN=xxx` or check `snyk_vulns.txt` for details |
| `Playwright not found` | Using `--spa` without Node.js | Install Node.js first, or skip `--spa` for standard mode |
| `Permission denied` | Workspace folder issues | `chmod +x JSJungleGym.sh` and check disk permissions |

---

## 💡 Pro Tips From a Grumpy Old Pentester

1. **Always test connectivity first**:  
   ```bash
   curl -I https://target.com
   ```

2. **False positives are normal**: Minified JS loves to name variables `password=`. Triage manually.

3. **Version matches are gold**: `jquery v1.2.3` → Google that version + "CVE" → profit (ethically).

4. **Rate limiting is your friend**: The script sleeps 1s between requests. Don't remove it unless you want to get IP banned.

5. **SPA mode is slower but smarter**: If the site feels like a single-page app, just use `--spa` and let Playwright do the heavy lifting.




## 🎪 Final Words

> *"Security isn't about having the shiniest tools. It's about asking the right questions, staying curious, and never stopping the hunt."*  
> — Your Friendly Neighborhood p4rham the newkid
