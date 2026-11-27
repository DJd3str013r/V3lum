"""Extract visible text from an untrusted HTML file (run with python3 -I).

usage: python3 -I html_text.py <path> [max_chars] [grep_regex]
Scripts/styles are skipped; control characters are escaped; nothing is executed.
With grep_regex, prints only +-200 char windows around each match.
"""
import re
import sys
from html.parser import HTMLParser


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.skip += 1
        if tag == "title":
            self._in_title = True
        if tag in ("p", "br", "div", "li", "h1", "h2", "h3", "h4", "tr", "pre", "code"):
            self.parts.append("\n")
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.parts.append(" [link:%s] " % href[:120])

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self.skip:
            self.skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if not self.skip:
            self.parts.append(data)


def esc(s):
    return "".join(ch if ch in "\n\t" or (32 <= ord(ch) < 127) or ord(ch) >= 160
                   else "\\x%02x" % ord(ch) for ch in s)


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 6000
    pat = sys.argv[3] if len(sys.argv) > 3 else None
    raw = open(path, "rb").read().decode("utf-8", "replace")
    p = _Text()
    p.feed(raw)
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(p.parts))
    text = re.sub(r"\n\s*\n+", "\n", text)
    print("# title:", esc(p.title.strip()))
    print("# text_chars:", len(text))
    if pat:
        for m in re.finditer(pat, text, re.I):
            a, b = max(0, m.start() - 200), min(len(text), m.end() + 200)
            print("---", esc(text[a:b]))
    else:
        print(esc(text[:limit]))


if __name__ == "__main__":
    main()
