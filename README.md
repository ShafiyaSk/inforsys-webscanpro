# Inforsys WebScanPro

Inforsys WebScanPro is an automated web vulnerability scanner built using Python.  
It detects common web security issues such as **SQL Injection**, **XSS**, and **IDOR**, and generates a professional **HTML Security Report**.  
The tool includes a Python crawler, vulnerability modules, and Docker environments (DVWA, Juice Shop, bWAPP) for safe testing.

## 🚀 Features

- Automated crawling of pages, links, and forms  
- SQL Injection detection  
- Cross-Site Scripting (XSS) detection  
- IDOR vulnerability detection  
- HTML security report generation  
- Docker support for vulnerable test apps  
- Fast and optimized scanning  
- Modular design for easy extension  

---

## 📁 Project Structure

inforsys-webscanpro/
│── crawler/
│ ├── spider.py
│ ├── utils.py
│── scanners/
│ ├── sql_injection.py
│ ├── xss.py
│ ├── idor.py
│── reports/
│ ├── report_generator.py
│── docker/
│ ├── dvwa-compose.yml
│ ├── juice-shop.yml
│── main.py
│── requirements.txt
│── README.md

📊 Security Report Output

Generated file:
security_report.html

Includes:

Vulnerability summary

Impact level

Affected URLs

Executive summary

🎯 Real-Time Uses

Student cybersecurity training

Web application penetration testing

Developer security analysis

Safe testing on Docker vulnerable apps

📝 Conclusion

Inforsys WebScanPro is a powerful and beginner-friendly automated scanner for learning and testing web vulnerabilities.
Its modular structure, Docker support, and detailed reporting make it ideal for security learning and research.
