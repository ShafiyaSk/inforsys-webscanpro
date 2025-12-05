# Inforsys WebScanPro

Inforsys WebScanPro is an automated web vulnerability scanner built using Python.  
It identifies common web application security issues such as **SQL Injection**, **Cross-Site Scripting (XSS)** and **Insecure Direct Object References (IDOR)**.  
The tool also generates a detailed **HTML Security Report** with findings and an executive summary.

---

## 🚀 Features

- Automated crawling of pages, links, and forms  
- SQL Injection detection  
- XSS (Cross-Site Scripting) detection  
- IDOR detection  
- HTML security report generation  
- Supports testing in safe, isolated Docker environments  
- Modular design — easy to extend with new vulnerability checks  

---

## 🐳 Docker Setup (Optional for Testing)

### Start DVWA  
```bash
docker-compose -f docker/dvwa-compose.yml up --build
Start Juice Shop
bash
Copy code
docker-compose -f docker/juice-shop.yml up --build
Start bWAPP
bash
Copy code
docker run -p 80:80 raesene/bwapp
▶️ Running WebScanPro
Install requirements:
bash
Copy code
pip install -r requirements.txt
Run a scan:
bash
Copy code
python main.py --url http://example.com
Output:
A detailed HTML security report will be generated at:

bash
Copy code
reports/security_report.html
🧪 Vulnerabilities Detected
🔹 SQL Injection
Detects unsafe SQL query patterns using standard payloads such as:
' OR 1=1 --

🔹 Cross-Site Scripting (XSS)
Detects reflected input-based XSS using payloads like:
<script>alert(1)</script>

🔹 IDOR
Checks for insecure access to resources through predictable object identifiers.

📘 Learning & Development Modules (Project Workflow)
Week	Module	Description
Week 1	Crawler	Extract URLs, forms, and inputs
Week 2	SQL Injection	Implement SQLi detection
Week 3	XSS	Implement XSS detection
Week 4	IDOR	Detect insecure resource access
Week 5	Docker	Setup DVWA, Juice Shop, bWAPP
Week 6	Reporting	Generate HTML security reports
Week 7	Integration	Combine all modules into WebScanPro

🎯 Purpose & Real-World Use
Learning ethical hacking and cybersecurity

Scanning web apps in a safe environment

Developer security testing

Hands-on practice with vulnerable apps using Docker

📝 Conclusion
Inforsys WebScanPro is a simple yet powerful automated security testing tool suitable for students, beginners, and developers.
Its modular design, detailed reports, and optional Docker support make it ideal for learning and real-world testing.
