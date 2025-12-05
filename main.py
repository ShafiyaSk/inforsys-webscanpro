import requests
from utils import *
from urllib.parse import urljoin
from datetime import datetime

TARGET = "http://testphp.vulnweb.com"
print("\n🚀 Starting WebScanPro\n")

visited = set()
pages = set()
all_forms = []
vulnerabilities = []

# ============================================================
# WEEK 2: SMART CRAWLING
# ============================================================

print("\n" + "="*60)
print("🔍 WEEK 2: SMART CRAWLING ENGINE STARTED")
print("="*60)

session = get_session()
queue = [TARGET]
MAX_PAGES = 500

while queue and len(pages) < MAX_PAGES:
    url = queue.pop(0)

    if url in visited:
        continue

    visited.add(url)

    try:
        print(f"🌐 Visiting: {url}")
        res = session.get(url, timeout=8)
        print(f"✅ Status: {res.status_code} - SUCCESS")
    except:
        print(f"❌ Failed to connect: {url}")
        continue

    if res.status_code != 200:
        continue

    pages.add(url)

    links = extract_links(res.text, url)
    forms = extract_forms(res.text, url)
    all_forms.extend(forms)

    print(f"📌 Links found: {len(links)} | Forms found: {len(forms)}")

    for link in links:
        if link and TARGET in link and link not in visited:
            queue.append(link)

print("\n✅ CRAWLING COMPLETED")
print(f"📄 Total Pages Crawled: {len(pages)}")
print(f"📋 Total Forms Found: {len(all_forms)}\n")


# ============================================================
# WEEK 3: SQL INJECTION TESTING
# ============================================================

print("\n" + "="*60)
print("💉 WEEK 3: SQL INJECTION SCANNING STARTED")
print("="*60)

sql_payload = "' OR '1'='1"
sql_found = 0

for idx, form in enumerate(all_forms):
    data = {inp['name']: sql_payload for inp in form['inputs'] if inp.get("name")}

    try:
        print(f"🧪 Testing Form {idx+1}/{len(all_forms)} → {form['action']}")

        if form['method'] == 'post':
            res = session.post(form['action'], data=data)
        else:
            res = session.get(form['action'], params=data)

        vulnerable, pat = find_sql_errors(res.text)

        if vulnerable:
            print("🚨 SQL INJECTION FOUND!")
            sql_found += 1
            vulnerabilities.append({
                "type": "SQL Injection",
                "endpoint": form['action'],
                "severity": "High",
                "mitigation": "Use parameterized queries & input validation"
            })
        else:
            print("✅ SAFE - No SQL Injection")

    except:
        print("❌ Error in SQL testing.")

if sql_found == 0:
    print("\n✅ NO SQL INJECTION FOUND\n")


# ============================================================
# WEEK 4: XSS TESTING
# ============================================================

print("\n" + "="*60)
print("⚠ WEEK 4: XSS SCANNING STARTED")
print("="*60)

xss_payload = "<script>alert(1)</script>"
xss_found = 0

for idx, form in enumerate(all_forms):
    data = {inp['name']: xss_payload for inp in form['inputs'] if inp.get("name")}

    try:
        print(f"🧪 Testing XSS {idx+1}/{len(all_forms)} → {form['action']}")

        if form['method'] == 'post':
            res = session.post(form['action'], data=data)
        else:
            res = session.get(form['action'], params=data)

        vulnerable, pat = find_xss_reflection(res.text)

        if vulnerable:
            print("🚨 XSS FOUND!")
            xss_found += 1
            vulnerabilities.append({
                "type": "Cross Site Scripting (XSS)",
                "endpoint": form['action'],
                "severity": "Medium",
                "mitigation": "Escape output & use CSP headers"
            })
        else:
            print("✅ SAFE - No XSS")

    except:
        print("❌ Error in XSS testing.")

if xss_found == 0:
    print("\n✅ NO XSS FOUND\n")


# ============================================================
# WEEK 5: AUTH TEST
# ============================================================

print("\n" + "="*60)
print("🔑 WEEK 5: AUTHENTICATION CHECK")
print("="*60)

auth_found = 0

for page in pages:
    if "login" in page.lower():
        print(f"⚠ Login page found: {page}")
        auth_found += 1
        vulnerabilities.append({
            "type": "Weak Authentication",
            "endpoint": page,
            "severity": "Low",
            "mitigation": "Add rate limiting & 2FA"
        })

if auth_found == 0:
    print("✅ No weak authentication detected\n")


# ============================================================
# WEEK 6: IDOR TEST
# ============================================================

print("\n" + "="*60)
print("🔓 WEEK 6: IDOR TESTING")
print("="*60)

idor_found = 0

for page in pages:
    if "id=1" in page:
        modified = page.replace("id=1", "id=2")

        try:
            print(f"🔄 Modifying ID: {modified}")
            r = session.get(modified)

            if r.status_code == 200:
                print("🚨 IDOR FOUND!")
                idor_found += 1
                vulnerabilities.append({
                    "type": "IDOR",
                    "endpoint": modified,
                    "severity": "High",
                    "mitigation": "Implement object-level authorization"
                })
            else:
                print("✅ SAFE - No IDOR")

        except:
            print("❌ Error during IDOR testing")

if idor_found == 0:
    print("\n✅ NO IDOR FOUND\n")


# ============================================================
# WEEK 7: ADVANCED REPORT GENERATION WITH EXECUTIVE SUMMARY AT END
# ============================================================

print("\n" + "="*60)
print("📄 WEEK 7: GENERATING SECURITY REPORT WITH EXECUTIVE SUMMARY AT END")
print("="*60)

high = sum(1 for v in vulnerabilities if v['severity'] == "High")
medium = sum(1 for v in vulnerabilities if v['severity'] == "Medium")
low = sum(1 for v in vulnerabilities if v['severity'] == "Low")

unique_vuln_pages = len(set(v['endpoint'] for v in vulnerabilities))

# Generate table rows
rows = ""
for v in vulnerabilities:
    severity_class = v['severity'].lower()  # "high", "medium", "low"
    rows += f"""
    <tr>
        <td>{v['type']}</td>
        <td>{v['endpoint']}</td>
        <td class="{severity_class}">{v['severity']}</td>
        <td>{v['mitigation']}</td>
    </tr>
    """

html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>WebScanPro Security Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {{
  background: radial-gradient(circle at top, #020617, #000);
  color: white;
  font-family: 'Segoe UI', sans-serif;
  padding: 40px;
  text-align: justify;
  text-justify: inter-word;
}}

h1, h2, h3 {{
  text-align: center;
  color: #38bdf8;
}}

.card {{
  background: linear-gradient(135deg, #020617, #1e293b);
  padding: 25px;
  margin: 25px auto;
  border-radius: 20px;
  box-shadow: 0 0 25px #0ea5e9;
  width: 90%;
  font-size: 18px;
  line-height: 1.8;
  letter-spacing: 0.5px;
  backdrop-filter: blur(8px);
}}

table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 40px;
  background: #020617;
  border-radius: 16px;
  overflow: hidden;
}}

th, td {{
  border: 1px solid #38bdf8;
  padding: 16px;
  font-size: 17px;
  word-wrap: break-word;
  word-break: break-all;
}}

th {{
  background: #0284c7;
}}

tr:nth-child(even) {{
  background: #020617;
}}

tr:hover {{
  background: rgba(56,189,248, 0.15);
  transition: 0.3s;
}}

.high {{
  color: #dc2626;
  font-weight: 700;
}}

.medium {{
  color: #f97316;
  font-weight: 600;
}}

.low {{
  color: #22c55e;
  font-weight: 600;
}}

.dashboard {{
  display: grid;
  grid-template-columns: repeat(2,1fr);
  gap: 35px;
  margin-top: 40px;
}}

.chart-box {{
  background: black;
  padding: 20px;
  border-radius: 18px;
  border: 2px solid #38bdf8;
  box-shadow: 0 0 20px #0284c7;
}}

canvas {{
  width: 100% !important;
  height: 350px !important;
}}

.remediation-box ul {{
  padding-left: 25px;
}}

.remediation-box li {{
  margin-bottom: 12px;
  line-height: 1.7;
}}

.executive-summary {{
  background: linear-gradient(135deg, #1e293b, #0f172a);
  border: 2px solid #38bdf8;
  border-radius: 20px;
  padding: 25px;
  width: 90%;
  margin: 25px auto;
  line-height: 1.8;
}}

.exec-item {{
  display: inline-block;
  width: 23%;
  background: #020617;
  border-radius: 12px;
  padding: 15px;
  margin: 5px;
  text-align: center;
  font-size: 16px;
  box-shadow: 0 0 15px #0284c7;
}}

.exec-item b {{
  display: block;
  margin-bottom: 8px;
  font-size: 20px;
  color: #38bdf8;
}}

@media print {{
  body {{
    background: white !important;
    color: black !important;
  }}
  .card, .chart-box, .executive-summary {{
    background: white !important;
    box-shadow: none !important;
    border: 1px solid #000 !important;
  }}
  table, th, td {{
    border: 1px solid black !important;
    color: black !important;
  }}
  th {{
    background: #eee !important;
  }}
  canvas {{
    display: none;
  }}
  h1, h2, h3 {{
    color: black !important;
  }}
}}
</style>
</head>

<body>

<h1>🔐 WebScanPro Advanced Security Report</h1>

<div class="card">
<b>Target:</b> {TARGET}<br><br>
<b>Scan Time:</b> {datetime.now()}<br>
<b>Total Pages:</b> {len(pages)}<br>
<b>Total Forms:</b> {len(all_forms)}<br>
<b>Total Vulnerabilities:</b> {len(vulnerabilities)}
</div>

<h2>📊 Visual Analytics Dashboard</h2>

<div class="dashboard">

  <div class="chart-box">
    <canvas id="barChart"></canvas>
    <h3>Severity Distribution</h3>
  </div>

  <div class="chart-box">
    <canvas id="pieChart"></canvas>
    <h3>Vulnerability Types</h3>
  </div>

  <div class="chart-box">
    <canvas id="donutChart"></canvas>
    <h3>Safe vs Vulnerable</h3>
  </div>

  <div class="chart-box">
    <canvas id="lineChart"></canvas>
    <h3>Phase-wise Risk</h3>
  </div>

</div>

<script>

new Chart(document.getElementById("barChart"), {{
  type: 'bar',
  data: {{
    labels:['High','Medium','Low'],
    datasets:[{{
      data:[{high},{medium},{low}],
      backgroundColor:['#ff0000','#ff9900','#00ff00']
    }}]
  }},
  options: {{ responsive:true }}
}});

new Chart(document.getElementById("pieChart"), {{
  type: 'pie',
  data: {{
    labels:['SQL','XSS','AUTH','IDOR'],
    datasets:[{{
      data:[{sql_found},{xss_found},{auth_found},{idor_found}],
      backgroundColor:['#ef4444','#f97316','#22c55e','#38bdf8']
    }}]
  }}
}});

new Chart(document.getElementById("donutChart"), {{
  type: 'doughnut',
  data: {{
   labels:['Safe','Vulnerable'],
   datasets:[{{
     data:[{len(pages)-unique_vuln_pages},{unique_vuln_pages}],
     backgroundColor:['#22c55e','#dc2626']
   }}]
  }}
}});

new Chart(document.getElementById("lineChart"), {{
  type: 'line',
  data: {{
    labels:['SQL','XSS','AUTH','IDOR'],
    datasets:[{{
      data:[{sql_found},{xss_found},{auth_found},{idor_found}],
      borderColor:'#38bdf8',
      fill:true,
      tension:0.4
    }}]
  }}
}});

</script>

<h2>📋 Detailed Vulnerability Table</h2>

<table>
<tr>
<th>Type</th>
<th>Endpoint</th>
<th>Severity</th>
<th>Mitigation</th>
</tr>

{rows if rows else '<tr><td colspan="4">✅ No vulnerabilities found</td></tr>'}

</table>

<div class="remediation-box">
<h2>✅ Suggested Remediations</h2>

<ul>
<li><b>SQL Injection:</b> Always use prepared statements, parameterized queries and ORM methods. Never concatenate user inputs into SQL queries.</li>
<li><b>Cross-Site Scripting (XSS):</b> Implement proper output encoding and use Content-Security-Policy (CSP) headers to restrict script execution.</li>
<li><b>Weak Authentication:</b> Enable multi-factor authentication (MFA) and enforce strong passwords with rate limiting and CAPTCHA.</li>
<li><b>IDOR Attacks:</b> Apply object-level authorization checks on the server side and never rely on user-controlled IDs.</li>
<li><b>Cookies:</b> Set HttpOnly, Secure, and SameSite flags on all session cookies.</li>
<li><b>Input Validation:</b> Use server-side validation and reject unexpected or malformed inputs.</li>
<li><b>Access Control:</b> Follow the principle of least privilege (PoLP) and verify permissions for every request.</li>
<li><b>Monitoring:</b> Enable logging and real-time alerting for suspicious activities.</li>
<li><b>Regular Testing:</b> Perform scheduled vulnerability scanning and code reviews.</li>
</ul>

</div>

<!-- Executive Summary at END -->
<div class="executive-summary">
  <h2>📌 Executive Summary</h2>
  <div class="exec-item"><b>{len(pages)}</b> Pages Scanned</div>
  <div class="exec-item"><b>{len(all_forms)}</b> Forms Detected</div>
  <div class="exec-item"><b>{len(vulnerabilities)}</b> Total Vulnerabilities</div>
  <div class="exec-item"><b>{high} High / {medium} Medium / {low} Low</b> Risk</div>
</div>


</body>
</html>
"""

with open("security_report.html", "w", encoding="utf-8") as f:
    f.write(html)

print("\n✅ ULTRA SECURITY REPORT GENERATED: security_report.html")
print("\n✨ Scan Completed Successfully ✨\n")
