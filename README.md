A **professional Linux security assessment tool** designed for system administrators, SOC analysts, penetration testers, and students.  
The script provides **comprehensive system audits** with multi-format reports (Text, JSON, HTML) and an overall **security score**.

---

## ✨ Features
- 🔍 **Multiple Audit Modes**
  - `--full` – Complete system audit (default)
  - `--ssh-only` – SSH configuration checks only
  - `--network` – Network checks only  
- 📊 **Reports** in **Text**, **JSON**, and **Interactive HTML Dashboard** formats  
- 📈 **Security Scoring System** (0–100) with warnings, issues, and recommendations  
- 🐧 **Kali Linux Detection** – additional health, repository, and VPN checks  
- ⚡ **Progress bar** and colored output for better UX  
- ✅ **Safe execution** with logging, timeout protection, and non-root support  

---

## 📋 Requirements
The following commands are required:
- `ss`, `ps`, `df`, `grep`, `awk`, `timeout`, `find`, `stat`

Optional but recommended:
- `jq`, `aide`, `docker`, `systemctl`, `sudo`

---

## 📥 Installation
Clone this repository and make the script executable:

```bash
git clone https://github.com/israel-elboim/sat-plus.git
cd sat-plus
chmod +x SAT.sh
