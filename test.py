

import streamlit as st

from url_anlysr import analyze_url
from database import create_database, save_scan, get_scan_history

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------



st.set_page_config(
    page_title="URL Safety Checker",
    page_icon="🛡️",
    layout="wide"
)




create_database()

# --------------------------------------------------
# WEBSITE DESIGN
# --------------------------------------------------

st.markdown("""
<style>

.stApp {
    background-color: #F3F6FC;
}

.main .block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

h1, h2, h3 {
    color: #102A43;
}

p, label {
    color: #334E68;
}

div.stButton > button {
    background-color: #87CEEB;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 0.6rem 1.5rem;
}

div.stButton > button:hover {
    background-color: #ADD8E6;
    color: white;
}

.result-card {
    background-color: white;
    padding: 22px;
    border-radius: 12px;
    border: 1px solid #D9E2F0;
    margin-bottom: 15px;
}

.safe {
    color: #16803C;
    font-weight: bold;
}

.suspicious {
    color: #C27C00;
    font-weight: bold;
}

.dangerous {
    color: #C62828;
    font-weight: bold;
}

.invalid {
    color: #C62828;
    font-weight: bold;
}

.unreachable {
    color: #6B7280;
    font-weight: bold;
}

</style>
""", unsafe_allow_html=True)

# --------------------------------------------------
# SIDEBAR NAVIGATION
# --------------------------------------------------

st.sidebar.title("🛡️ URL Safety Checker")

page = st.sidebar.radio(
    "Navigation",
    [
        "Home",
        "Scan History",
        "About",
        "Help"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info(
    "Analyze website URLs using domain, DNS, "
    "HTTPS, and suspicious-pattern checks."
)

# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

if page == "Home":

    st.title("🛡️ URL Safety Checker")

    st.markdown(
        "### Check a website URL before visiting it."
    )

    st.write(
        "Enter a website address below to analyze its "
        "domain structure, DNS availability, HTTPS connection, "
        "and suspicious indicators."
    )

    st.markdown("---")

    url_input = st.text_input(
        "Enter Website URL",
        placeholder="Example: https://google.com"
    )

    scan_button = st.button(
        "🔍 Scan URL",
        use_container_width=True
    )

    if scan_button:

        if not url_input.strip():

            st.warning("Please enter a URL before scanning.")

        else:

            with st.spinner("Analyzing the URL. Please wait..."):

                result = analyze_url(url_input)

            # Save Invalid and Unreachable as -1.
            # Zero is reserved for a completed analysis with no risk points.

            saved_score = result["risk_score"]

            if result["status"] in ["Invalid", "Unreachable"]:
                saved_score = -1

            save_scan(
                result["url"],
                result["domain"],
                saved_score,
                result["status"]
            )

            st.markdown("---")
            st.subheader("Analysis Result")

            # ------------------------------------------
            # RESULT SUMMARY
            # ------------------------------------------

            status = result["status"]
            score = result["risk_score"]

            if status == "Safe":
                st.success("Website classification: SAFE")

            elif status == "Suspicious":
                st.warning("Website classification: SUSPICIOUS")

            elif status == "Dangerous":
                st.error("Website classification: DANGEROUS")

            elif status == "Invalid":
                st.error("Website classification: INVALID URL")

            elif status == "Unreachable":
                st.warning("Website classification: UNREACHABLE")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**Website URL**")
                st.write(result["url"])

            with col2:
                st.markdown("**Domain**")
                st.write(result["domain"] or "Not available")

            st.markdown("---")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**Risk Score**")

                if status in ["Invalid", "Unreachable"]:
                    st.subheader("Not assessed")
                    st.caption(
                        "The analysis could not be completed. "
                        "A score of 0 is not being treated as safe."
                    )
                else:
                    st.subheader(f"{score}/100")
                    st.progress(score / 100)

            with col2:
                st.markdown("**Final Status**")
                st.subheader(status)

            # ------------------------------------------
            # ANALYSIS COMPLETION MESSAGE
            # ------------------------------------------

            if result["analysis_complete"]:
                st.success(
                    "The configured URL analysis checks have been completed."
                )
            else:
                st.warning(
                    "The analysis could not be completed. "
                    "Please review the findings below."
                )

            # ------------------------------------------
            # SEVEN ANALYSIS STAGES
            # ------------------------------------------

            st.markdown("---")
            st.subheader("Detailed Security Analysis")

            for index, check in enumerate(result["checks"], start=1):

                with st.expander(
                    f"Stage {index}: {check['stage']} — {check['status']}"
                ):

                    st.write(check["details"])

            # ------------------------------------------
            # FINDINGS
            # ------------------------------------------

            st.markdown("---")
            st.subheader("Security Findings")

            if result["issues"]:

                for issue in result["issues"]:
                    st.write("• " + issue)

            else:
                st.write("No findings were recorded.")

            # ------------------------------------------
            # IMPORTANT LIMITATION
            # ------------------------------------------

            st.info(
                "Important: This project uses rule-based URL analysis. "
                "It does not check a live threat-intelligence database. "
                "A Safe result means no configured warning indicators "
                "were detected; it does not guarantee that the website "
                "is harmless."
            )

# --------------------------------------------------
# SCAN HISTORY PAGE
# --------------------------------------------------

elif page == "Scan History":

    st.title("📋 Scan History")

    st.write(
        "View the URLs previously analyzed using this application."
    )

    history = get_scan_history()

    if history:

        history_data = []

        for row in history:

            # Handle dictionary records
            if isinstance(row, dict):

                url = row.get("Website URL", row.get("url", ""))
                domain = row.get("Domain", row.get("domain", ""))
                risk_score = row.get(
                    "Risk Score",
                    row.get("Risk Score/100", row.get("risk_score", -1))
                )
                status = row.get(
                    "Status",
                    row.get("status", "")
                )
                scan_time = row.get(
                    "Scan Date & Time",
                    row.get("Scan Time", row.get("scan_time", ""))
                )

            # Handle tuple records
            else:

                url, domain, risk_score, status, scan_time = row

            # Format risk score
            if risk_score == -1 or risk_score is None:
                display_score = "Not assessed"
            else:
                display_score = f"{risk_score}/100"

            history_data.append({
                "Domain": domain,
                "Website URL": url,
                "Risk Score/100": display_score,
                "Status": status,
                "Scan Date & Time": scan_time
            })

        st.dataframe(
            history_data,
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            f"Total scans recorded: {len(history_data)}"
        )

    else:

        st.info(
            "No scan history is available yet. "
            "Scan a URL from the Home page to get started."
        )

# --------------------------------------------------
# ABOUT PAGE
# --------------------------------------------------

elif page == "About":

    st.title("ℹ️ About URL Safety Checker")

    st.write("""
    URL Safety Checker is a Python-based web application
    built using Streamlit.

    Its purpose is to analyze website URLs and identify
    potentially suspicious characteristics.
    """)

    st.subheader("Main Features")

    features = [
        "URL format validation",
        "Domain validation",
        "DNS and IP address verification",
        "HTTPS and SSL certificate checks",
        "Suspicious URL indicator detection",
        "Risk score calculation",
        "Scan history using SQLite database"
    ]

    for feature in features:
        st.write("✅ " + feature)

    st.subheader("Technology Used")

    st.write("""
    - Python
    - Streamlit
    - SQLite
    - Socket and SSL libraries
    - Regular expressions
    """)

    st.info(
        "The application does not use a paid threat-intelligence API. "
        "Its findings are based on locally implemented checks."
    )

# --------------------------------------------------
# HELP PAGE
# --------------------------------------------------

elif page == "Help":

    st.title("❓ Help")

    st.subheader("How to use the website")

    st.write("""
    1. Open the Home page.
    2. Enter a website URL.
    3. Click the Scan URL button.
    4. Wait for the analysis to finish.
    5. Review the risk score and final classification.
    6. Expand the seven analysis stages to see details.
    7. Open Scan History to view previous scans.
    """)

    st.markdown("---")

    st.subheader("Understanding Risk Scores")

    st.write("""
    - 0–15: Safe classification based on configured checks
    - 16–40: Suspicious
    - 41–100: Dangerous
    """)

    st.subheader("Other Statuses")

    st.write("""
    - Invalid: The URL or domain format is invalid.
    - Unreachable: DNS could not resolve the domain to an IP address.
    - Not assessed: A risk score could not be calculated because
      the analysis stopped early.
    """)

    st.warning(
        "A Safe classification is not a guarantee. "
        "The application does not verify URLs against a live "
        "malicious-website database."
    )
