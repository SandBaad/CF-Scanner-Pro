"""Terminal plumbing: colors, glyph sets, full-screen drawing and single-key input.

Pure standard library, works on Linux, macOS, Termux and Windows 10+.
"""
import os
import sys

IS_WIN = os.name == "nt"


def enable_windows_ansi():
    if not IS_WIN:
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        for handle_id in (-11, -12):  # stdout, stderr
            h = k32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(h, ctypes.byref(mode)):
                k32.SetConsoleMode(h, mode.value | 0x0004)  # VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


def wants_color(stream, forced_off=False):
    if forced_off or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM") != "dumb"


def can_unicode(stream):
    try:
        "╭─│━✓●…".encode(getattr(stream, "encoding", None) or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


STYLES = {
    "title": "1;38;5;51", "accent": "38;5;45", "accent2": "38;5;81", "border": "38;5;31",
    "frame": "38;5;239", "bold": "1", "ip": "1;38;5;255", "text": "38;5;252",
    "dim": "38;5;245", "muted": "38;5;239", "good": "38;5;114", "goodb": "1;38;5;114",
    "warn": "38;5;221", "bad": "38;5;203", "info": "38;5;111", "magenta": "38;5;176",
    "colo": "38;5;180", "key": "1;38;5;16;48;5;45", "keyw": "1;38;5;16;48;5;221",
    "head": "1;38;5;81",
}


class Theme:
    def __init__(self, color=True, unicode=True):
        self.color = color
        self.unicode = unicode
        if unicode:
            self.tl, self.tr, self.bl, self.br, self.h, self.v = "╭", "╮", "╰", "╯", "─", "│"
            self.bar, self.ell, self.done, self.cur, self.todo = "━", "…", "✓", "●", "○"
            self.dot, self.arrow, self.cross, self.dash = "·", "→", "×", "—"
        else:
            self.tl = self.tr = self.bl = self.br = "+"
            self.h, self.v = "-", "|"
            self.bar, self.ell, self.done, self.cur, self.todo = "=", "~", "+", ">", "-"
            self.dot, self.arrow, self.cross, self.dash = "|", "->", "x", "-"

    def paint(self, text, style=None):
        if not style or not self.color or not text:
            return text
        return f"\x1b[{STYLES.get(style, style)}m{text}\x1b[0m"


class Screen:
    """Alternate screen with flicker-free whole-frame redraws."""

    def __init__(self, stream=None):
        self.out = stream or sys.stdout

    def __enter__(self):
        self.out.write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
        self.out.flush()
        return self

    def __exit__(self, *exc):
        self.out.write("\x1b[0m\x1b[?25h\x1b[?1049l")
        self.out.flush()

    def draw(self, lines):
        buf = ["\x1b[?2026h"]  # synchronized update (ignored where unsupported)
        for row, line in enumerate(lines, 1):
            buf.append(f"\x1b[{row};1H{line}\x1b[0m")
        buf.append("\x1b[0J\x1b[?2026l")
        self.out.write("".join(buf))
        self.out.flush()


class Keys:
    """Non-blocking single-key reader (q / n). Ctrl+C keeps working as usual."""

    def __init__(self):
        self.fd = None
        self.saved = None

    def __enter__(self):
        if IS_WIN or not sys.stdin.isatty():
            return self
        try:
            import termios
            import tty
            self.fd = sys.stdin.fileno()
            self.saved = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)  # no echo, no line buffering, signals still on
        except Exception:
            self.fd = self.saved = None
        return self

    def __exit__(self, *exc):
        if self.saved is not None:
            import termios
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)

    def read(self):
        keys = []
        if IS_WIN:
            try:
                import msvcrt
                while msvcrt.kbhit():
                    keys.append(msvcrt.getwch())
            except Exception:
                pass
            return keys
        if self.fd is None:
            return keys
        import select
        while select.select([self.fd], [], [], 0)[0]:
            data = os.read(self.fd, 64)
            if not data:
                break
            keys.extend(data.decode("utf-8", "ignore"))
        return keys
