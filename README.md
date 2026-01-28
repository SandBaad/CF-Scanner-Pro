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
<pre dir="ltr">
git clone https://github.com/SandBaad/CF-Scanner-Pro.git
cd CF-Scanner-Pro
</pre>pre>
2. **Install requirements:**
<pre dir="ltr">
pip install -r requirements.txt
</pre>pre>
3. **Run the tool:**
<pre dir="ltr">
python main.py
</pre>pre>
### Usage
Run the script and enter your SNI (Target Domain) when prompted.
- **Secure Mode:** Scans a random sample of IPs (slower, less likely to be blocked).
- **Aggressive Mode:** Scans sequentially with higher threads.

---

<a name="persian"></a>
<div dir="ltr">

<h2>🇮🇷 فارسی</h2>
</div>
<div dir="rtl">
<p>
ابزار <b>CF-Scanner Pro</b> برای اسکن رنج‌های آی‌پی کلودفلر طراحی شده است. این اسکریپت با انجام <code>TLS Handshake</code> روی دامنه (SNI) مورد نظر شما، سالم بودن آی‌پی را بررسی کرده و پینگ آن را نمایش می‌دهد.
</p>

<h3>✨ ویژگی‌ها</h3>
<ul>
  <li><b>رابط کاربری:</b> استفاده از محیط گرافیکی در ترمینال.</li>
  <li><b>چند نخی (Multi-thread):</b> بررسی همزمان چندین آی‌پی برای سرعت بیشتر.</li>
  <li><b>حالت‌های اسکن:</b> دارای حالت‌های <code>Secure</code> (تصادفی) و <code>Aggressive</code> (سریع).</li>
  <li><b>ذخیره خودکار:</b> آی‌پی‌های سالم در فایل <code>working_ips.txt</code> ذخیره می‌شوند.</li>
</ul>

<h3>📦 نصب و اجرا</h3>

<p>۱. <b>دریافت پروژه:</b></p>

<pre dir="ltr">
git clone https://github.com/SandBaad/CF-Scanner-Pro.git
cd CF-Scanner-Pro
</pre>

<p>۲. <b>نصب پیش‌نیازها:</b></p>

<pre dir="ltr">
  pip install -r requirements.txt
</pre>

<p>۳. <b>اجرا:</b></p>

<pre dir="ltr">
python main.py
</pre>

<h3>🚀 راهنما</h3>
<p>بعد از اجرا، دامنه (SNI) خود را وارد کنید.</p>
<ul>
  <li><b>حالت Secure:</b> از هر رنج تعدادی آی‌پی را به صورت تصادفی انتخاب و اسکن می‌کند.</li>
  <li><b>حالت Aggressive:</b> تمام آی‌پی‌ها را با سرعت بالا اسکن می‌کند.</li>
</ul>

</div>

---

## Disclaimer
This tool is for educational purposes and network analysis only.
