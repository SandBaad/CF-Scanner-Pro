# CF-Scanner Pro

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

**Find working Cloudflare edge IPs for your own SNI - fast, from your terminal.**

[English](#english) • [فارسی](#persian)

---

<a name="english"></a>
## English

### Features
- **Async engine** - hundreds of parallel checks with a single thread and low memory (great on Termux).
- **Smart scan** - samples every /24, digs deeper only into blocks that respond, then re-tests the best IPs to measure median latency and packet loss.
- **Real verification** - TCP → TLS handshake with your SNI (certificate checked) → `/cdn-cgi/trace` request, which also reveals the Cloudflare colo.
- **Live dashboard** - progress, speed, ETA, failure breakdown and best IPs; adapts to narrow screens.
- **Diagnostics** - tells you *why* nothing worked (e.g. SNI filtered, domain not proxied).
- **Safe output** - results are written while scanning; Ctrl+C stops cleanly and saves.

### Install
```bash
git clone https://github.com/SandBaad/CF-Scanner-Pro.git
cd CF-Scanner-Pro
pip install -r requirements.txt
python main.py
```
Termux: `pkg install python git` first.

### Modes
| Mode  | What it does |
|-------|--------------|
| Smart | 2 IPs from each /24 → +30 IPs in every responding /24 → re-test the best 30. Stops at 100 IPs. |
| Quick | 1 IP from each /24 → re-test the best 20. |
| Full  | Every IP in the ranges (≈1.5M - slow). |

### Command line
```bash
python main.py --sni sub.example.com --mode smart
python main.py --sni sub.example.com --target 50 --colo FRA,AMS
python main.py -y                 # start with saved settings
python main.py --update-ranges    # refresh subnets.txt from Cloudflare
```
Other flags: `-c/--concurrency`, `-t/--timeout`, `--subnets FILE`, `--no-verify`, `--no-http`.

### Output
- `working_ips.txt` - working IPs, best first.
- `results.csv` - TLS/TCP latency, colo, median and loss for every IP found.

> Your SNI domain must be proxied by Cloudflare (orange cloud) for the HTTP check. Otherwise use `--no-http`.

---

<a name="persian"></a>
<div dir="rtl">

## فارسی

**CF-Scanner Pro** آی‌پی‌های سالم کلودفلر را برای دامنه (SNI) شما پیدا می‌کند.

### ویژگی‌ها
- **موتور async:** صدها تست همزمان با مصرف رم کم؛ مناسب Termux.
- **اسکن هوشمند:** از هر رنج /24 نمونه می‌گیرد، فقط رنج‌های سالم را عمیق‌تر می‌گردد و بهترین آی‌پی‌ها را چند بار دوباره تست می‌کند (میانه پینگ و درصد loss).
- **تست واقعی:** اتصال TCP، سپس TLS با SNI شما (با بررسی گواهی)، سپس درخواست `/cdn-cgi/trace` که دیتاسنتر (colo) را هم نشان می‌دهد.
- **داشبورد زنده:** پیشرفت، سرعت، زمان باقی‌مانده، آمار خطاها و بهترین آی‌پی‌ها.
- **عیب‌یابی:** اگر چیزی پیدا نشود، دلیل احتمالی را می‌گوید (مثلاً فیلتر بودن SNI).
- **ذخیره امن:** نتایج حین اسکن ذخیره می‌شوند و Ctrl+C اسکن را تمیز متوقف می‌کند.

### نصب و اجرا

<div dir="ltr">

```bash
git clone https://github.com/SandBaad/CF-Scanner-Pro.git
cd CF-Scanner-Pro
pip install -r requirements.txt
python main.py
```

</div>

### حالت‌ها
- **Smart (پیشنهادی):** از هر /24 دو آی‌پی، سپس ۳۰ آی‌پی بیشتر از رنج‌های سالم، سپس تست مجدد ۳۰ آی‌پی برتر.
- **Quick:** از هر /24 یک آی‌پی؛ سریع‌ترین حالت.
- **Full:** همه آی‌پی‌ها (کند).

### خروجی
- فایل `working_ips.txt`: آی‌پی‌های سالم، مرتب از بهترین.
- فایل `results.csv`: جزئیات پینگ، دیتاسنتر و loss.

> برای تست HTTP، دامنه شما باید پشت پروکسی کلودفلر (ابر نارنجی) باشد؛ در غیر این صورت از `--no-http` استفاده کنید.

</div>

---

## Disclaimer
This tool is for educational purposes and network analysis only.
