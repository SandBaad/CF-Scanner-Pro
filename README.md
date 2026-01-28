# CF-Scanner Pro

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

<div align="center">
  <p>
    <strong>A Python tool to scan and verify Cloudflare IPs based on custom SNI.</strong>
  </p>
  <p>
    <a href="#english">English</a> •
    <a href="#persian">فارسی</a>
  </p>
</div>

---

<a name="english"></a>
## English Documentation

**CF-Scanner Pro** is a script designed to scan Cloudflare IP ranges. It performs a TLS Handshake with your specified SNI to verify if the IP is working and measures the latency.

### Features
- **TUI:** Terminal interface using `Rich` library.
- **Multi-threading:** Scans multiple IPs concurrently.
- **Modes:** Includes Secure (random sampling) and Aggressive modes.
- **Auto-Save:** Saves working IPs to `working_ips.txt`.

### Installation

1. **Clone the repository:**

    git clone https://github.com/SandBaad/CF-Scanner-Pro.git
    cd CF-Scanner-Pro

2. **Install requirements:**

    pip install -r requirements.txt

3. **Run the tool:**

    python main.py

### Usage
Run the script and enter your SNI (Target Domain) when prompted.
- **Secure Mode:** Scans a random sample of IPs (slower, less likely to be blocked).
- **Aggressive Mode:** Scans sequentially with higher threads.

---

<a name="persian"></a>
<div dir="rtl">

## مستندات فارسی

**CF-Scanner Pro** ابزاری برای اسکن رنج‌های آی‌پی کلودفلر است. این اسکریپت با انجام TLS Handshake روی دامنه (SNI) مورد نظر شما، سالم بودن آی‌پی را بررسی کرده و پینگ آن را نمایش می‌دهد.

### ویژگی‌ها
- **رابط کاربری:** استفاده از محیط گرافیکی در ترمینال.
- **چند نخی (Multi-thread):** بررسی همزمان چندین آی‌پی برای سرعت بیشتر.
- **حالت‌های اسکن:** دارای حالت‌های Secure (تصادفی) و Aggressive (سریع).
- **ذخیره خودکار:** آی‌پی‌های سالم در فایل `working_ips.txt` ذخیره می‌شوند.

### نصب و اجرا

۱. **دریافت پروژه:**

    git clone https://github.com/SandBaad/CF-Scanner-Pro.git
    cd CF-Scanner-Pro

۲. **نصب پیش‌نیازها:**

    pip install -r requirements.txt

۳. **اجرا:**

    python main.py

### راهنما
بعد از اجرا، دامنه (SNI) خود را وارد کنید.
* **حالت Secure:** از هر رنج تعدادی آی‌پی را به صورت تصادفی انتخاب و اسکن می‌کند.
* **حالت Aggressive:** تمام آی‌پی‌ها را با سرعت بالا اسکن می‌کند.

</div>

---

## Disclaimer
This tool is for educational purposes and network analysis only.
