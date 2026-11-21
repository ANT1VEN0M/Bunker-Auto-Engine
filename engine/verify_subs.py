import sys
import base64
import urllib.parse
from engine.xray_checker import test_xray_batch

def verify_file(filepath, sample_size=20):
    with open(filepath, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    
    # decode base64 if needed
    if len(lines) == 1 and not lines[0].startswith(("vless://", "vmess://", "trojan://", "ss://")):
        try:
            raw = base64.b64decode(lines[0]).decode("utf-8", errors="ignore")
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
        except Exception:
            pass

    print(f"Total links in {filepath}: {len(lines)}")
    sample = lines[:sample_size]
    cfgs = []
    for l in sample:
        # simple parse to cfg
        u = urllib.parse.urlsplit(l)
        cfgs.append({
            "proto": u.scheme,
            "raw": l,
            "server": u.hostname,
            "port": u.port or 443,
            "name": urllib.parse.unquote(u.fragment)
        })
    
    working = test_xray_batch(cfgs)
    print(f"--- Verification result for {filepath} ---")
    print(f"Tested {len(sample)} nodes: {len(working)} PASSED HTTP 204 ({len(working)*100//len(sample)}%)")
    for w in working[:5]:
        print(f"  [OK] {w.get('name')} | ping: {w.get('ping_ms')}ms")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "sub/mix.txt"
    verify_file(path)
