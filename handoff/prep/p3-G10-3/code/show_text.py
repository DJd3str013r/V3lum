"""Print an untrusted text file safely (control characters escaped), optionally a byte range. Run with python3 -I."""
import sys


def main():
    path = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    length = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
    with open(path, "rb") as fh:
        data = fh.read()
    text = data[start:start + length].decode("utf-8", "replace")
    out = []
    for ch in text:
        if ch in "\n\t" or (ord(ch) >= 32 and not (0x7f <= ord(ch) <= 0x9f)):
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}")
    print("".join(out))
    print(f"--- {len(data)} bytes total")


if __name__ == "__main__":
    main()
