![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

# iptables-access-tester

🛡️ A small Python script to **check if a given source IP and destination TCP port would be accepted or blocked** based on your current `iptables` rules.

It does **not simulate traffic**. It parses your system's `iptables` rules and evaluates whether a connection would match a rule, and what the action would be.

---

## 🔍 Example usage

```bash
sudo python3 test_iptables.py 192.168.1.50 22
```

Example output:

```
✅ ACCEPTED by rule:
-A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
```

or

```
❌ BLOCKED by rule:
-A INPUT -s 0.0.0.0/0 -p tcp --dport 22 -j DROP
```

or

```
⚠️ No matching rule found — default policy is: DROP
```

---

## 📦 Installation

No external dependencies required.

Clone the repo and make the script executable:

```bash
git clone https://github.com/<your_username>/iptables-access-tester.git
cd iptables-access-tester
chmod +x test_iptables.py
```

---

## ▶️ Usage

```bash
sudo ./test_iptables.py <source_ip> <destination_port>
```

Example:

```bash
sudo ./test_iptables.py 10.0.0.42 443
```

ℹ️ The script inspects only the **INPUT** chain and supports **TCP** rules (`-p tcp`).

---

## ✅ Features

- ✅ Matches rules based on `-s <IP>` and `--dport <PORT>`
- ✅ Supports `ACCEPT`, `DROP`, and `REJECT` targets
- ✅ Fallbacks to the default INPUT policy if no matching rule is found
- ❌ Does not yet support UDP or custom chains
- ❌ Ignores advanced matching (stateful, interfaces, etc.)

---

## 🧪 Quick test script

Create a simple `test.sh` file to run common checks:

```bash
#!/bin/bash

echo "== Test SSH from 192.168.1.100 =="
sudo python3 test_iptables.py 192.168.1.100 22

echo "== Test HTTPS from 10.0.0.5 =="
sudo python3 test_iptables.py 10.0.0.5 443
```

---

## 📝 License

MIT – free to use, modify, and share.

Pull requests welcome!
