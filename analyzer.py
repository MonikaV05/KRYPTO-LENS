import sys, json, re, math
from urllib.parse import urlparse

COMMON = {"password","123456","12345678","qwerty","abc123","letmein","admin","welcome","iloveyou","monkey","dragon","111111","passw0rd","password1","123456789"}
KW = ["login","verify","secure","account","update","bank","paypal","signin","confirm","wallet","password","gift","free"]
BAD_TLD = (".zip",".xyz",".top",".tk",".click",".gq",".ml",".work",".country")
SHORT = {"bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy"}
URG = ["urgent","immediately","act now","suspended","verify your","confirm your","unusual activity","limited time","click here","password expires","final notice","you have won","claim your","security alert"]
ASK = ["password","ssn","social security","credit card","otp","pin","bank account","cvv","gift card","wire transfer"]
BAD_EXT = (".exe",".scr",".js",".vbs",".iso",".docm",".xlsm",".bat",".jar",".html")


def verdict(s):
    return "Dangerous" if s >= 60 else "Suspicious" if s >= 30 else "Safe"


def url_scan(u):
    flags, score = [], 0
    u = u.strip()
    p = urlparse(u if "://" in u else "http://" + u)
    host = (p.hostname or "").lower()
    if not host:
        return {"score": 100, "verdict": "Dangerous", "flags": ["Not a valid URL"]}
    checks = [
        (p.scheme != "https", 15, "Connection is not encrypted (no HTTPS)"),
        (bool(re.fullmatch(r"[\d.]+", host)), 30, "Uses a raw IP address instead of a domain"),
        ("@" in u, 25, "Contains '@' which can hide the real destination"),
        (host.count(".") >= 4, 15, "Unusually many subdomains"),
        (host.startswith("xn--") or "xn--" in host, 25, "Punycode domain (look-alike characters)"),
        (len(u) > 90, 10, "Very long URL"),
        (host.endswith(BAD_TLD), 20, "High-risk top-level domain"),
        (host in SHORT, 15, "URL shortener hides the final destination"),
        (host.count("-") >= 3, 10, "Many hyphens in domain"),
    ]
    hits = [k for k in KW if k in (host + p.path).lower()]
    if len(hits) >= 2:
        checks.append((True, 20, "Sensitive keywords in URL: " + ", ".join(hits[:4])))
    for cond, pts, msg in checks:
        if cond:
            score += pts
            flags.append(msg)
    score = min(score, 100)
    if not flags:
        flags.append("No suspicious patterns found")
    return {"score": score, "verdict": verdict(score), "flags": flags}


def text_scan(t, email=False):
    low, flags, score = t.lower(), [], 0
    urg = [k for k in URG if k in low]
    ask = [k for k in ASK if k in low]
    if urg:
        score += min(15 * len(urg), 35)
        flags.append("Urgency / pressure wording: " + ", ".join(urg[:4]))
    if ask:
        score += min(15 * len(ask), 35)
        flags.append("Asks for sensitive data: " + ", ".join(ask[:4]))
    links = re.findall(r"https?://[^\s<>\"']+", t)
    worst = 0
    for l in links[:5]:
        r = url_scan(l)
        worst = max(worst, r["score"])
    if links:
        flags.append(f"{len(links)} link(s) found, riskiest scored {worst}/100")
        score += worst // 3
    if email:
        frm = re.search(r"^from:.*?<?([\w.+-]+@[\w.-]+)>?", t, re.I | re.M)
        rep = re.search(r"^reply-to:.*?<?([\w.+-]+@[\w.-]+)>?", t, re.I | re.M)
        if frm and rep and frm.group(1).split("@")[1] != rep.group(1).split("@")[1]:
            score += 25
            flags.append("From and Reply-To domains do not match")
        if any(e in low for e in BAD_EXT) and "attach" in low:
            score += 20
            flags.append("Mentions a risky attachment type")
        if re.search(r"dear (customer|user|member)", low):
            score += 10
            flags.append("Generic greeting instead of your name")
    if not flags:
        flags.append("No suspicious patterns found")
    score = min(score, 100)
    return {"score": score, "verdict": verdict(score), "flags": flags}


def pw_scan(p):
    flags, pool = [], 0
    for rx, n in ((r"[a-z]", 26), (r"[A-Z]", 26), (r"\d", 10), (r"[^\w]", 32)):
        if re.search(rx, p):
            pool += n
    ent = round(len(p) * math.log2(pool), 1) if pool else 0
    score = min(int(ent / 80 * 100), 100)
    if len(p) < 12:
        flags.append("Use at least 12 characters")
    if p.lower() in COMMON or any(c in p.lower() for c in ("password", "qwerty", "admin")):
        score = min(score, 10)
        flags.append("Contains a very common password pattern")
    if re.search(r"(.)\1{2,}", p):
        score -= 15
        flags.append("Repeated characters (aaa, 111)")
    if re.search(r"(0123|1234|2345|abcd|bcde)", p.lower()):
        score -= 15
        flags.append("Sequential characters")
    for rx, msg in ((r"[a-z]", "Add lowercase letters"), (r"[A-Z]", "Add uppercase letters"), (r"\d", "Add numbers"), (r"[^\w]", "Add symbols")):
        if not re.search(rx, p):
            flags.append(msg)
    score = max(0, min(score, 100))
    label = "Strong" if score >= 75 else "Medium" if score >= 45 else "Weak"
    if not flags:
        flags.append("Great password. Store it in a password manager.")
    return {"score": score, "verdict": label, "flags": flags, "entropy": ent}


if __name__ == "__main__":
    try:
        d = json.load(sys.stdin)
        t = str(d.get("type", ""))
        x = str(d.get("data", ""))
        fn = {
            "url": url_scan,
            "phishing": text_scan,
            "password": pw_scan,
            "email": lambda s: text_scan(s, True),
            "qr": text_scan
        }.get(t)
        if fn is None:
            # Fallback if unknown scan type passed
            fn = text_scan
        print(json.dumps(fn(x)))
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)