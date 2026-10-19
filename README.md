🛡️ AI Phishing Email Analyzer

A Python and Streamlit cybersecurity project for analyzing email content and identifying potential phishing indicators.

🔗 Project Links

GitHub Repository: https://github.com/Koripelli-geetha/AI-Phishing-Email-Analyzer

Author: Geetha Koripalli

📌 Project Overview

Phishing is a common cybersecurity threat in which attackers use deceptive emails and links to trick people into revealing sensitive information, visiting fraudulent websites, or downloading malicious files.

The AI Phishing Email Analyzer is an educational security tool designed to examine email content, extract URLs, identify suspicious patterns, calculate a risk score, and present findings through a simple web interface.

This project demonstrates practical skills in Python programming, email parsing, URL analysis, defensive security, and security report generation.

Note: The current version uses programmed detection rules. It is not yet a trained machine-learning model.

🎯 Project Objectives

Analyze suspicious email content.

Extract URLs from plain-text and HTML emails.

Identify potentially suspicious URL structures.

Calculate a risk score using configured indicators.

Display findings and recommended actions.

Generate downloadable analysis reports.

Practice defensive cybersecurity and Python development.

✨ Key Features

1. Email Analysis

Analyze email subject, sender, and message body.

Upload and parse .eml email files.

Inspect HTML email content when provided.

Identify suspicious words and phrases.

2. Advanced URL Analysis

Extract URLs from email content and HTML.

Flag links that use HTTP instead of HTTPS.

Identify URL shorteners such as bit.ly.

Detect IP addresses used as URL hosts.

Flag potentially misleading URL structures involving @.

Display extracted URLs and associated warnings.

3. Risk Assessment

Calculate a risk score using configured detection rules.

Classify results as Low, Medium, or High risk.

Display suspicious indicators and recommended actions.

4. Security Reporting

Display analysis summary metrics.

Show extracted URLs and warnings.

Download reports in TXT and PDF formats.

🛠️ Technologies Used

Python

Streamlit

Regular Expressions

HTMLParser

Python Email Parsing

URL Parsing

Git and GitHub

Kali Linux

🧪 Safe URL Testing Examples

These examples demonstrate URL patterns that can be tested by the analyzer. They are illustrative examples, not confirmed malicious websites.

Test Case

Example

Purpose

HTTP URL

http://example.com/login

Check HTTP warning behavior

URL shortener

https://bit.ly/example

Check shortener detection

IP-based URL

http://192.0.2.10/login

Check IP host detection

Misleading URL structure

http://example.com@192.0.2.10/

Check URL parsing warnings

Ordinary example URL

https://example.com/

Compare detection behavior

The results depend on the rules implemented in the application. These examples do not guarantee a particular risk score.

🚀 Installation and Setup

Prerequisites

Python 3

pip

Git

Kali Linux or another compatible Python environment

Step 1: Clone the repository

git clone https://github.com/Koripelli-geetha/AI-Phishing-Email-Analyzer.git
cd AI-Phishing-Email-Analyzer

Step 2: Create a virtual environment

python3 -m venv .venv

Step 3: Activate the environment

source .venv/bin/activate

Step 4: Install Streamlit

pip install streamlit

Install any other dependencies required by the application.

Step 5: Run the application

streamlit run app.py

Open the local address displayed in your terminal, usually:

http://localhost:8501

📖 How to Use

Start the Streamlit application.

Enter an email subject, sender, and body, or upload an .eml file.

Submit the email for analysis.

Review the risk score and risk classification.

Examine extracted URLs and warnings.

Read the findings and recommended actions.

Download the report if required.

📁 Project Structure

AI-Phishing-Email-Analyzer/
├── app.py
├── .gitignore
├── README.md
├── backups/
├── reports/
├── samples/
├── screenshots/
├── src/
└── tests/

🔐 Security and Limitations

A high risk score does not prove that an email is malicious.

A low risk score does not guarantee that an email is safe.

HTTPS does not automatically mean that a website is trustworthy.

Legitimate URLs may sometimes trigger warnings.

Suspicious URLs may escape detection.

This tool is for educational and defensive security use.

Do not publish passwords, API keys, private email data, or active malicious links. Use sanitized samples for public demonstrations.

🔮 Future Enhancements

Add a requirements.txt file for dependency management.

Expand automated unit tests.

Improve hostname and URL validation.

Integrate reputable threat-intelligence services.

Explore machine-learning-based phishing classification.

Add screenshots and more detailed test reports.

Deploy a safe public demonstration.

👩‍💻 Author

Geetha Koripalli

Cybersecurity Portfolio Project

GitHub Profile: https://github.com/Koripelli-geetha

Project Repository: https://github.com/Koripelli-geetha/AI-Phishing-Email-Analyzer

Disclaimer: This project is intended for educational and defensive cybersecurity purposes only.
