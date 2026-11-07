"""Renders docs/screenshot.png from the real dashboard code (example data, not a measurement).

Every character is drawn into its own grid cell, so the picture is aligned in any viewer.
Needs Pillow and DejaVu Sans Mono:  python3 docs/render_screenshot.py
"""
import os
import random
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

from cfscan.engine import Hit  # noqa: E402
from cfscan.scanner import ScanState  # noqa: E402
from cfscan.term import Theme  # noqa: E402
from cfscan.tui import Dashboard  # noqa: E402

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
W, H, S = 112, 31, 2


def example_state():
    rng = random.Random(3)
    st = ScanState()
    st.phases = ["Discovery", "Expansion", "Verify", "Speed"]
    st.begin_phase("Speed", 10)
    st.phase_done, st.rate = 6, 0.8
    st.tested, st.live_blocks = 12476, 1931
    st.fails.update(tcp=9874, tls=2096, cert=12, http=31)
    for i in range(40):
        ip = f"{rng.choice([104, 172, 162, 188])}.{rng.randint(16, 30)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        h = Hit(ip, 70 + rng.randint(0, 60), 140 + rng.randint(0, 120), rng.choice(["FRA", "AMS", "IST", "VIE", "WAW", "DXB"]))
        h.apply_rounds([h.tcp + rng.randint(-5, 5) for _ in range(5)],
                       [h.tls + rng.randint(-10, 12) for _ in range(5)], 5 if rng.random() > .2 else 6)
        if i % 3 == 0:
            h.speed = rng.choice([6.2, 11.8, 18.4, 27.9, 33.5, 41.0])
        st.add_hit(h)
    st.found = 538
    st.logs.clear()
    t = time.mktime((2026, 11, 7, 18, 40, 0, 0, 0, -1))
    for dt, msg, lvl in [(0, "Discovery: 11,904 checks", "info"), (41, "1,931 of 5,952 /24 blocks answered", "good"),
                         (41, "Expansion: 600 checks", "info"), (58, "Verified 40 IPs - 33 with zero loss", "good"),
                         (58, "Download test via speed.cloudflare.com", "info")]:
        st.logs.append((time.strftime("%H:%M:%S", time.localtime(t + dt)), msg, lvl))
    st._start = time.monotonic() - 63
    return st


def x256(n):
    base = [(0, 0, 0), (205, 49, 49), (13, 188, 121), (229, 229, 16), (36, 114, 200), (188, 63, 188), (17, 168, 205),
            (229, 229, 229), (102, 102, 102), (241, 76, 76), (35, 209, 139), (245, 245, 67), (59, 142, 234),
            (214, 112, 214), (41, 184, 219), (255, 255, 255)]
    if n < 16:
        return base[n]
    if n < 232:
        n -= 16
        v = [0, 95, 135, 175, 215, 255]
        return (v[n // 36], v[n // 6 % 6], v[n % 6])
    c = 8 + (n - 232) * 10
    return (c, c, c)


def render(lines, path, title="cfscan scan sub.example.com"):
    fs = 15 * S
    font = ImageFont.truetype(f"{FONT_DIR}/DejaVuSansMono.ttf", fs)
    fontb = ImageFont.truetype(f"{FONT_DIR}/DejaVuSansMono-Bold.ttf", fs)
    cw, ch, pad, top = round(font.getlength("M")), round(fs * 1.32), 18 * S, 34 * S
    bg0, fg0 = (11, 17, 22), (213, 221, 226)
    img = Image.new("RGB", (W * cw + 2 * pad, H * ch + 2 * pad + top), bg0)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, img.width, top], fill=(17, 26, 32))
    for i, c in enumerate([(255, 95, 87), (254, 188, 46), (40, 200, 64)]):
        d.ellipse([pad + i * 22 * S, 12 * S, pad + i * 22 * S + 11 * S, 23 * S], fill=c)
    d.text((pad + 80 * S, 9 * S), title, font=font, fill=(127, 147, 158))
    tok = re.compile(r"\x1b\[([0-9;]*)m|([^\x1b])")
    for row, line in enumerate(lines):
        fg, bg, bold, col = fg0, None, False, 0
        for m in tok.finditer(line):
            if m.group(2) is None:
                nums = [int(x) for x in m.group(1).split(";") if x] or [0]
                i = 0
                while i < len(nums):
                    n = nums[i]
                    if n == 0:
                        fg, bg, bold = fg0, None, False
                    elif n == 1:
                        bold = True
                    elif n in (38, 48):
                        if n == 38:
                            fg = x256(nums[i + 2])
                        else:
                            bg = x256(nums[i + 2])
                        i += 2
                    i += 1
                continue
            x, y, c = pad + col * cw, pad + top + row * ch, m.group(2)
            if bg:
                d.rectangle([x, y, x + cw, y + ch], fill=bg)
            if c == "█":
                d.rectangle([x, y + ch * .18, x + cw - 1, y + ch * .82], fill=fg)
            elif c == "░":
                d.rectangle([x, y + ch * .42, x + cw - 1, y + ch * .58], fill=fg)
            elif c in "─│┌┐└┘":
                mx, my = x + cw // 2, y + ch // 2
                segs = {"─": [(x, my, x + cw, my)], "│": [(mx, y, mx, y + ch)],
                        "┌": [(mx, my, x + cw, my), (mx, my, mx, y + ch)], "┐": [(x, my, mx, my), (mx, my, mx, y + ch)],
                        "└": [(mx, y, mx, my), (mx, my, x + cw, my)], "┘": [(mx, y, mx, my), (x, my, mx, my)]}[c]
                for s in segs:
                    d.line(s, fill=fg, width=S)
            elif c != " ":
                d.text((x, y + (ch - fs) // 2 - S), c, font=fontb if bold else font, fill=fg)
            col += 1
    img.save(path, optimize=True)


if __name__ == "__main__":
    cfg = dict(sni="sub.example.com", mode="smart", concurrency=200, timeout=2.5, port=443)
    lines = Dashboard(example_state(), cfg, Theme(color=True, unicode=True), "working_ips.txt").render(W, H)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshot.png")
    render(lines, out)
    print("wrote", out)
