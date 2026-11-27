"""Print the visible text of an untrusted HTML file (python3 -I html_text.py FILE [MAXCHARS] [GREP]).

stdlib html.parser only; scripts/styles dropped; control characters escaped by peek._safe-like logic.
"""
import re
import sys
from html.parser import HTMLParser


class _T(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self._skip += 1
        if tag in ("p", "br", "div", "li", "h1", "h2", "h3", "h4", "tr", "section"):
            self.parts.append("\n")
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.parts.append(" [link:%s] " % href)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _safe(s):
    return "".join(ch if ch in "\n\t" or (0x20 <= ord(ch) < 0x7F) or ord(ch) >= 0xA0 else "\\u%04x" % ord(ch) for ch in s)


def main(argv):
    raw = open(argv[1], "rb").read().decode("utf-8", errors="replace")
    t = _T()
    t.feed(raw)
    text = re.sub(r"[ \t]+", " ", "".join(t.parts))
    text = re.sub(r"\n\s*\n+", "\n", text)
    limit = int(argv[2]) if len(argv) > 2 else 8000
    if len(argv) > 3:
        pat = re.compile(argv[3], re.I)
        lines = [ln for ln in text.splitlines() if pat.search(ln)]
        text = "\n".join(lines)
    print(_safe(text[:limit]))


if __name__ == "__main__":
    main(sys.argv)
