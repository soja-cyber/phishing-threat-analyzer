import streamlit as st
import re
import base64
import requests
from urllib.parse import urlparse

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Phishing Threat Analyzer",
    page_icon="🛡️",
    layout="centered"
)

# --- SECURE API KEY MANAGEMENT ---
# The app checks the cloud for a hidden secure key. If it doesn't find one (like when running on your local PC), it uses the hardcoded key.
if "VT_API_KEY" in st.secrets:
    VT_API_KEY = st.secrets["VT_API_KEY"]
else:
    VT_API_KEY = "F2886d1681183e7c787ff1bc58227848bbce0254ebf100a98a03b22323ba3a58"

def heuristic_check(url):
    """Local offline inspection algorithm."""
    risk_score = 0
    flags = []

    domain = urlparse(url).netloc.split(':')[0]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        risk_score += 3
        flags.append("Uses raw IP address instead of domain name.")
        
    if "@" in url:
        risk_score += 3
        flags.append("Contains '@' symbol to obscure destination.")

    sensitive_keywords = ["login", "verify", "update", "banking", "secure", "signin", "account"]
    if any(word in url.lower() for word in sensitive_keywords):
        risk_score += 2
        flags.append("Contains high-risk credential keywords.")

    if url.startswith("http://"):
        risk_score += 1
        flags.append("Uses unencrypted HTTP connection.")

    return risk_score, flags

def scan_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(api_endpoint, headers=headers, timeout=4)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious'] + stats['suspicious']
            clean = stats['harmless'] + stats['undetected']
            return "online", malicious, clean, None
        else:
            # URL not found in database or API error -> run heuristic fallback
            score, flags = heuristic_check(url)
            return "heuristic", score, flags, "URL not in database or network restricted."
            
    except requests.exceptions.RequestException:
        # Offline network issue -> run heuristic fallback
        score, flags = heuristic_check(url)
        return "heuristic", score, flags, "Internet connection offline."

# --- WEB INTERFACE ---
st.title("🛡️ Cyber Threat Analyzer")
st.caption("Real-Time Phishing & Fraud Detector")

st.markdown("---")

url_input = st.text_input("Enter URL / Link to scan:", placeholder="https://example.com/login")

if st.button("Analyze Link", type="primary"):
    if not url_input:
        st.warning("Please enter a URL first.")
    else:
        with st.spinner("Analyzing link structure and threat intelligence database..."):
            mode, res1, res2, note = scan_url(url_input)

        st.subheader("Analysis Results")

        if mode == "online":
            st.info("📡 **Data Source:** VirusTotal Threat Intelligence Engine")
            
            col1, col2 = st.columns(2)
            col1.metric("Flagged Malicious", f"{res1} Vendors")
            col2.metric("Flagged Safe", f"{res2} Vendors")

            if res1 > 0:
                st.error("🚨 **VERDICT: HIGH RISK** — This link is flagged as malicious by global security databases.")
            else:
                st.success("✅ **VERDICT: LOW RISK** — No vendor flags detected for this URL.")

        else:  # Heuristic Fallback
            st.warning(f"⚙️ **Data Source:** Offline Heuristic Engine ({note})")
            risk_score, flags = res1, res2

            st.metric("Risk Score", f"{risk_score} / 9")

            if risk_score >= 3:
                st.error("🚨 **VERDICT: HIGH RISK** — Suspicious structural patterns detected.")
            elif risk_score > 0:
                st.warning("⚠️️ **VERDICT: MEDIUM RISK** — Exercise caution with this link.")
            else:
                st.success("✅ **VERDICT: LOW RISK** — No suspicious patterns identified.")

            if flags:
                st.markdown("**Triggered Risk Flags:**")
                for flag in flags:
                    st.write(f"- ⚠️️ {flag}")
