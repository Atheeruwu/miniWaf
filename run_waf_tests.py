import urllib.request, urllib.error

tests = [
    ("Allow /", "http://127.0.0.1:8080/", 200),
    ("Block XSS", "http://127.0.0.1:8080/search?q=<script>alert(1)</script>", 403),
    ("Block SQLi", "http://127.0.0.1:8080/search?q=1%20OR%201=1", 403),
    ("Block Traversal", "http://127.0.0.1:8080/../../etc/passwd", 403),
]

def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read(200).decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200).decode(errors="ignore")
    except Exception as e:
        return None, str(e)

for name, url, expected in tests:
    status, body = fetch(url)
    ok = (status == expected)
    status_label = "PASS" if ok else "FAIL"
    print(f"{status_label} - {name} | expected {expected}, got {status}")
    if not ok:
        print("  body:", body.replace("\n", " ")[:120])
print("All tests completed.")
