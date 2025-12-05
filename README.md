Inforsys WebScanPro

Inforsys WebScanPro is an automated web vulnerability scanner built using Python.
It scans web applications for common security issues like SQL Injection, XSS, and IDOR, and generates a detailed HTML Security Report.
The project includes a Python-based crawler, vulnerability modules, and Docker-based vulnerable test environments (DVWA / Juice Shop / bWAPP).

🚀 Features

🔍 Automated crawling of all pages, forms, links, and input fields

🛡 Vulnerability Scanning

SQL Injection

Cross-Site Scripting (XSS)

Insecure Direct Object References (IDOR)

📊 Generates an HTML Security Report with executive summary

🐳 Docker support for testing on DVWA, Juice Shop, and bWAPP

⚡ Fast, optimized scanning

🧪 Weekly module-wise development structure for learning

💡 Easily extendable with custom vulnerability modules

📁 Project Structure
inforsys-webscanpro/
│── crawler/
│   ├── spider.py
│   ├── utils.py
│── scanners/
│   ├── sql_injection.py
│   ├── xss.py
│   ├── idor.py
│── reports/
│   ├── report_generator.py
│── docker/
│   ├── dvwa-compose.yml
│   ├── juice-shop.yml
│── main.py
│── requirements.txt
│── README.md

🐳 Docker Setup

Use Docker to safely test your scanner on vulnerable web apps:

Start DVWA
docker-compose -f docker/dvwa-compose.yml up --build

Start Juice Shop
docker-compose -f docker/juice-shop.yml up --build

Start bWAPP Container
docker run -p 80:80 raesene/bwapp

▶️ How to Run WebScanPro

Install requirements:

pip install -r requirements.txt


Run the scanner:

python main.py --url http://example.com


After scanning, an HTML report will be generated in:

/reports/security_report.html

🧪 Vulnerabilities Detected
1️⃣ SQL Injection

Detects reflected and boolean-based injections

Tests with payloads like ' OR 1=1 --

2️⃣ XSS

Checks input fields for JavaScript injection

Tests with <script>alert(1)</script> patterns

3️⃣ IDOR

Checks insecure object access patterns

Detects predictable parameter values

📄 Weekly Learning Modules
Week	Module	Description
Week 1	Crawler	Build URL extractor & form parser
Week 2	SQLi Scanner	Implement payload-based tests
Week 3	XSS Scanner	Detect reflected/stored XSS
Week 4	IDOR Scanner	Detect predictable resource access
Week 5	Docker Setup	Run DVWA, Juice Shop, bWAPP
Week 6	Report Generator	Generate HTML report
Week 7	Final Integration	Combine all modules into WebScanPro
📊 Security Report Sample Output

Generated file:

security_report.html


Includes:

Vulnerability summary

Impact analysis

Affected URLs

Executive summary

🎯 Real-Time Uses

Students learning ethical hacking

Security teams scanning internal web apps

Developers testing their application security

Training on real vulnerable apps using Docker

📝 Conclusion

Inforsys WebScanPro provides a safe, automated, and powerful solution for learning cyber security and scanning web applications.
Its modular design makes it easy to extend, and Docker support makes testing secure and realistic.
