import textwrap
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import streamlit as st
import re
import ipaddress
import os
import html as html_lib
from urllib.parse import urlparse, unquote
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

# ---------------- PAGE SETTINGS ----------------


def make_pdf_report(report_text):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Phishing Email Analysis Report")
    y -= 30
    pdf.setFont("Helvetica", 9)

    for line in report_text.splitlines():
        wrapped_lines = textwrap.wrap(line, width=95) or [""]
        for wrapped in wrapped_lines:
            if y < 45:
                pdf.showPage()
                pdf.setFont("Helvetica", 9)
                y = height - 50

            # Keep the PDF compatible with the built-in font.
            safe_line = wrapped.encode(
                "latin-1", "replace"
            ).decode("latin-1")

            pdf.drawString(50, y, safe_line)
            y -= 13

    pdf.save()
    buffer.seek(0)
    return buffer.getvalue()


st.set_page_config(
    page_title="AI Phishing Email Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Phishing Email Analyzer")
st.write(
    "Analyze email text, HTML links, and .eml files for common "
    "phishing indicators. This tool provides warnings, not a final verdict."
)

# ---------------- DETECTION SETTINGS ----------------

SUSPICIOUS_WORDS = [
    "urgent", "verify your account", "password expires",
    "account suspended", "unusual activity", "confirm your identity",
    "click here", "immediately", "payment failed",
    "update your payment", "wire transfer", "gift card",
    "login to your account", "reset your password",
    "you have won", "limited time", "security alert"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at"
}

# ---------------- HTML LINK EXTRACTION ----------------

class EmailLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.current_anchor = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag.lower() == "a":
            self.current_anchor = {
                "visible_text": "",
                "href": attrs.get("href", "")
            }

        elif tag.lower() in ("iframe", "form"):
            self.links.append({
                "visible_text": f"[HTML {tag}]",
                "href": attrs.get("src", "") or attrs.get("action", "")
            })

    def handle_data(self, data):
        if self.current_anchor is not None:
            self.current_anchor["visible_text"] += data

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.current_anchor is not None:
            self.links.append(self.current_anchor)
            self.current_anchor = None


def extract_html_links(html_content):
    parser = EmailLinkParser()
    try:
        parser.feed(html_content)
    except Exception:
        pass
    return parser.links


# ---------------- URL EXTRACTION ----------------

URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"'()\]]+"""
)


def normalize_url(raw_url):
    url = html_lib.unescape(raw_url.strip())
    url = url.rstrip(".,;!?")
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def extract_urls(text):
    return [normalize_url(x) for x in URL_PATTERN.findall(text or "")]


def inspect_url(url):
    result = []
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        result.append("URL has no recognizable hostname.")
        return result

    if parsed.scheme.lower() == "http":
        result.append("Uses HTTP instead of HTTPS; traffic may not be encrypted.")

    if "@" in parsed.netloc:
        result.append("Contains '@' in the URL authority, which can disguise the destination.")

    try:
        ipaddress.ip_address(hostname)
        result.append("Uses a raw IP address instead of a domain name.")
    except ValueError:
        pass

    if hostname in SHORTENERS:
        result.append("Uses a known URL-shortening domain; the final destination is hidden.")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        result.append("Contains an internationalized/punycode hostname; inspect for lookalike characters.")

    if hostname.count(".") >= 4:
        result.append("Hostname has many subdomains; check whether the actual domain is trustworthy.")

    if hostname.startswith("secure-") or "login-" in hostname or "verify-" in hostname:
        result.append("Hostname contains words often used to imitate trusted login pages.")

    if len(url) > 150:
        result.append("Unusually long URL; inspect the full destination carefully.")

    if parsed.username or parsed.password:
        result.append("Contains user information before the hostname, which may be misleading.")

    if not result:
        result.append("No basic URL warning detected. This does not prove the link is safe.")

    return result


def visible_text_mismatch(visible_text, destination):
    visible_text = (visible_text or "").strip()
    destination = (destination or "").strip()

    if not visible_text or not destination:
        return False

    visible_urls = extract_urls(visible_text)
    if not visible_urls:
        return False

    def host(url):
        return (urlparse(normalize_url(url)).hostname or "").lower()

    return any(host(link) != host(destination) for link in visible_urls)


# ---------------- EMAIL PARSING ----------------

def parse_eml(uploaded_file):
    raw = uploaded_file.getvalue()

    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Please upload an email file smaller than 2 MB.")

    message = BytesParser(policy=policy.default).parsebytes(raw)

    subject = str(message.get("subject", "(No subject)"))
    sender = str(message.get("from", "(Unknown sender)"))

    text_parts = []
    html_parts = []

    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if not isinstance(content, str):
            continue

        if content_type == "text/plain":
            text_parts.append(content)
        else:
            html_parts.append(content)

    return subject, sender, "\n".join(text_parts), "\n".join(html_parts)


# ---------------- RISK ANALYSIS ----------------

def analyze_email(subject, sender, body, html_content):
    findings = []
    score = 0
    combined_text = f"{subject}\n{sender}\n{body}\n{html_content}".lower()

    found_words = sorted({
        word for word in SUSPICIOUS_WORDS if word in combined_text
    })

    if found_words:
        score += min(30, len(found_words) * 5)
        findings.append(
            "Urgent or suspicious language: " + ", ".join(found_words)
        )

    sender_name, sender_address = parseaddr(sender)
    if sender_address and "@" in sender_address:
        domain = sender_address.rsplit("@", 1)[-1].lower()

        if domain in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}:
            findings.append(
                "Sender uses a public email provider. This alone does not mean it is phishing."
            )

        if sender_address.count("@") > 1:
            score += 15
            findings.append("Sender address contains multiple @ symbols.")

    urls = extract_urls(body)
    html_links = extract_html_links(html_content)

    for link in html_links:
        destination = normalize_url(link.get("href", ""))
        if destination.startswith(("http://", "https://")):
            urls.append(destination)

    unique_urls = list(dict.fromkeys(urls))

    if unique_urls:
        findings.append(f"Found {len(unique_urls)} unique URL(s).")

    for link in html_links:
        destination = normalize_url(link.get("href", ""))
        visible = link.get("visible_text", "")

        if destination.startswith(("http://", "https://")):
            if visible_text_mismatch(visible, destination):
                score += 20
                findings.append(
                    f"Visible link text does not match destination: "
                    f"'{visible.strip()[:80]}' -> {destination}"
                )

    url_findings = []
    for url in unique_urls:
        warnings = inspect_url(url)
        for warning in warnings:
            if warning.startswith("Uses HTTP"):
                score += 10
            elif warning.startswith("Uses a known URL-shortening"):
                score += 15
            elif warning.startswith("Uses a raw IP"):
                score += 20
            elif warning.startswith("Contains '@'"):
                score += 20
            # The user-information warning is displayed but not scored separately
            # because it overlaps with the '@' authority warning.
            elif warning.startswith("Hostname has many"):
                score += 10
            elif warning.startswith("Unusually long"):
                score += 5
            elif warning.startswith("Hostname contains"):
                score += 10

            url_findings.append((url, warning))

    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    if not findings:
        findings.append("No obvious suspicious keywords or mismatched links detected.")

    return score, level, findings, unique_urls, url_findings


# ---------------- USER INTERFACE ----------------

tab_text, tab_file = st.tabs(["Analyze Email Text", "Upload .eml File"])

with tab_text:
    st.subheader("Analyze an email message")

    subject_input = st.text_input("Email subject")
    sender_input = st.text_input("Sender email address")
    body_input = st.text_area("Paste email body text", height=200)
    html_input = st.text_area(
        "Optional: Paste HTML email source",
        height=150,
        help="Paste the HTML source if you want to inspect hidden link destinations."
    )

    if st.button("Analyze Email Text", type="primary"):
        score, level, findings, urls, url_findings = analyze_email(
            subject_input, sender_input, body_input, html_input
        )

        st.metric("Risk Score", f"{score}/100")
        st.subheader(f"Risk Level: {level}")

        if level == "High":
            st.error("High risk: review this email carefully.")
        elif level == "Medium":
            st.warning("Medium risk: investigate the warning signs.")
        else:
            st.info("Low detected risk: this does not guarantee safety.")

        if level == "High":
            st.subheader("Recommended Action")
            st.write(
                "Avoid clicking links or opening attachments until you "
                "verify the email. Contact the sender through a trusted "
                "channel if needed."
            )
        elif level == "Medium":
            st.subheader("Recommended Action")
            st.write(
                "Check the sender and inspect suspicious links carefully. "
                "Do not provide passwords or personal information unless "
                "you independently verify the request."
            )
        else:
            st.subheader("Recommended Action")
            st.write(
                "No obvious warning signs were detected. Still be careful "
                "with unexpected requests, links, and attachments."
            )

        st.subheader("Analysis Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", f"{score}/100")
        col2.metric("URLs Found", len(urls))
        col3.metric("URL Warnings", len(url_findings))

        st.subheader("Analysis Findings")
        for finding in findings:
            st.write("- " + finding)

        st.subheader("Extracted URLs")
        if urls:
            for url in urls:
                st.code(url)
        else:
            st.write("No URLs detected.")

        if level == "High":
            recommended_action = (
                "Avoid clicking links or opening attachments until you verify the email. "
                "Contact the sender through a trusted channel if needed."
            )
        elif level == "Medium":
            recommended_action = (
                "Check the sender and inspect suspicious links carefully. "
                "Do not provide passwords or personal information unless you independently "
                "verify the request."
            )
        else:
            recommended_action = (
                "No obvious warning signs were detected. Still be careful with "
                "unexpected requests, links, and attachments."
            )

        report_lines = [
            "AI Phishing Email Analyzer - Analysis Report",
            "=" * 45,
            f"Risk Score: {score}/100",
            f"Risk Level: {level}",
            "",
            "Recommended Action:",
            recommended_action,
            "",
            "Analysis Findings:",
        ]
        if findings:
            report_lines.extend(f"- {finding}" for finding in findings)
        else:
            report_lines.append("- No findings recorded")

        report_lines.extend(["", "Extracted URLs:"])
        if urls:
            report_lines.extend(f"- {url}" for url in urls)
        else:
            report_lines.append("- No URLs found")

        report_lines.extend(["", "URL Warnings:"])
        if url_findings:
            report_lines.extend(
                f"- {url} — {warning}" for url, warning in url_findings
            )
        else:
            report_lines.append("- No URL warnings detected")

        report_text = "\n".join(report_lines) + "\n"

        st.download_button(
            label="Download Analysis Report (.txt)",
            data=report_text,
            file_name="phishing_analysis_report.txt",
            mime="text/plain",
            key="download_text_report",
            on_click="ignore",
        )

        st.download_button(
            label="Download Analysis Report (.pdf)",
            data=make_pdf_report(report_text),
            file_name="phishing_analysis_report.pdf",
            mime="application/pdf",
            key="download_pdf_report",
            on_click="ignore",
        )

        st.subheader("URL Warnings")
        if url_findings:
            for url, warning in url_findings:
                st.write(f"- **{url}** — {warning}")
        else:
            st.write("No basic URL warnings detected.")


with tab_file:
    st.subheader("Upload an email file")
    st.write("Upload a trusted sample or suspicious email saved as a .eml file.")
    uploaded_file = st.file_uploader(
        "Choose an .eml file",
        type=["eml"],
        help="Files larger than 2 MB are rejected."
    )

    if uploaded_file is not None:
        try:
            subject, sender, body, html_content = parse_eml(uploaded_file)

            st.write("**Subject:**", subject)
            st.write("**Sender:**", sender)

            with st.expander("View extracted email text"):
                st.text(body[:10000] or "(No plain-text body found)")
            with st.expander("View extracted HTML source"):
                st.code(html_content[:10000] or "(No HTML body found)")

            if st.button("Analyze Uploaded Email", type="primary"):
                score, level, findings, urls, url_findings = analyze_email(
                    subject, sender, body, html_content
                )

                st.metric("Risk Score", f"{score}/100")
                st.subheader(f"Risk Level: {level}")

                if level == "High":
                    st.error("High risk: review this email carefully.")
                elif level == "Medium":
                    st.warning("Medium risk: investigate the warning signs.")
                else:
                    st.info("Low detected risk: this does not guarantee safety.")

                if level == "High":
                    st.subheader("Recommended Action")
                    st.write(
                        "Avoid clicking links or opening attachments until you "
                        "verify the email. Contact the sender through a trusted "
                        "channel if needed."
                    )
                elif level == "Medium":
                    st.subheader("Recommended Action")
                    st.write(
                        "Check the sender and inspect suspicious links carefully. "
                        "Do not provide passwords or personal information unless "
                        "you independently verify the request."
                    )
                else:
                    st.subheader("Recommended Action")
                    st.write(
                        "No obvious warning signs were detected. Still be careful "
                        "with unexpected requests, links, and attachments."
                    )

                st.subheader("Analysis Summary")
                col1, col2, col3 = st.columns(3)
                col1.metric("Risk Score", f"{score}/100")
                col2.metric("URLs Found", len(urls))
                col3.metric("URL Warnings", len(url_findings))

                st.subheader("Analysis Findings")
                for finding in findings:
                    st.write("- " + finding)

                st.subheader("Extracted URLs")
                if urls:
                    for url in urls:
                        st.code(url)
                else:
                    st.write("No URLs detected.")

                if level == "High":
                    recommended_action = (
                        "Avoid clicking links or opening attachments until you verify the email. "
                        "Contact the sender through a trusted channel if needed."
                    )
                elif level == "Medium":
                    recommended_action = (
                        "Check the sender and inspect suspicious links carefully. "
                        "Do not provide passwords or personal information unless you independently "
                        "verify the request."
                    )
                else:
                    recommended_action = (
                        "No obvious warning signs were detected. Still be careful with "
                        "unexpected requests, links, and attachments."
                    )

                report_lines = [
                    "AI Phishing Email Analyzer - Analysis Report",
                    "=" * 45,
                    f"Risk Score: {score}/100",
                    f"Risk Level: {level}",
                    "",
                    "Recommended Action:",
                    recommended_action,
                    "",
                    "Analysis Findings:",
                ]
                if findings:
                    report_lines.extend(f"- {finding}" for finding in findings)
                else:
                    report_lines.append("- No findings recorded")

                report_lines.extend(["", "Extracted URLs:"])
                if urls:
                    report_lines.extend(f"- {url}" for url in urls)
                else:
                    report_lines.append("- No URLs found")

                report_lines.extend(["", "URL Warnings:"])
                if url_findings:
                    report_lines.extend(
                        f"- {url} — {warning}" for url, warning in url_findings
                    )
                else:
                    report_lines.append("- No URL warnings detected")

                report_text = "\n".join(report_lines) + "\n"

                st.download_button(
                    label="Download Analysis Report (.txt)",
                    data=report_text,
                    file_name="phishing_analysis_report.txt",
                    mime="text/plain",
                    key="download_eml_report",
                    on_click="ignore",
                )

                st.download_button(
                    label="Download Analysis Report (.pdf)",
                    data=make_pdf_report(report_text),
                    file_name="phishing_analysis_report.pdf",
                    mime="application/pdf",
                    key="download_eml_pdf_report",
                    on_click="ignore",
                )

                st.subheader("URL Warnings")
                if url_findings:
                    for url, warning in url_findings:
                        st.write(f"- **{url}** — {warning}")
                else:
                    st.write("No basic URL warnings detected.")

        except Exception as error:
            st.error(f"Could not read this email file: {error}")


st.divider()
st.caption(
    "Educational tool only. Risk scores are heuristic, not proof of phishing. "
    "Do not enter passwords or open suspicious links. The analyzer does not "
    "visit URLs or guarantee that a message is safe."
)
