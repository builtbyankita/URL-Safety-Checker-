

import socket
import ssl
import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs

# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

SUSPICIOUS_WORDS = [
    "login", "verify", "verification", "account",
    "update", "secure", "signin", "password",
    "banking", "confirm", "wallet", "payment",
    "free-gift", "prize", "claim", "urgent"
]

REDIRECT_PARAMETERS = [
    "redirect", "redirect_url", "return",
    "return_url", "next", "url", "target"
]

KNOWN_BRANDS = [
    "google", "microsoft", "apple", "amazon",
    "paypal", "facebook", "instagram", "netflix",
    "whatsapp", "telegram", "bankofamerica"
]

# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def make_result(url, domain, score, status, issues,
                analysis_complete, checks):

    return {
        "url": url,
        "domain": domain,
        "risk_score": score,
        "status": status,
        "issues": issues,
        "analysis_complete": analysis_complete,
        "checks": checks
    }

def calculate_entropy(text):
    """Measure how unpredictable a string's characters are."""

    if not text:
        return 0

    entropy = 0

    for character in set(text):
        probability = text.count(character) / len(text)
        entropy -= probability * math.log2(probability)

    return entropy

def resolve_domain(domain):
    """Check whether the domain resolves to an IP address."""

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            proto=socket.IPPROTO_TCP
        )

        ip_addresses = sorted({
            result[4][0] for result in results
        })

        return True, ip_addresses

    except socket.gaierror:
        return False, []

    except OSError:
        return False, []

def check_ssl_certificate(domain):
    """Check the HTTPS certificate."""

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=domain
            ) as secure_connection:

                certificate = secure_connection.getpeercert()

                if certificate:
                    return True, "Valid HTTPS certificate."

                return False, "Certificate information unavailable."

    except ssl.SSLCertVerificationError:
        return False, "SSL certificate verification failed."

    except (ssl.SSLError, OSError, TimeoutError):
        return False, "Could not establish a verified HTTPS connection."

def is_ip_address(domain):
    """Determine whether the hostname is an IP address."""

    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def check_domain_pattern(domain):
    """Look for unusual domain-name patterns."""

    findings = []
    score = 0

    main_domain = domain.split(".")[0]

    if len(main_domain) > 20:
        findings.append("The main domain name is unusually long.")
        score += 10

    if main_domain.count("-") >= 3:
        findings.append("The domain contains several hyphens.")
        score += 10

    if re.search(r"\d{4,}", main_domain):
        findings.append("The domain contains a long sequence of numbers.")
        score += 10

    if len(main_domain) >= 12:
        entropy = calculate_entropy(main_domain)

        if entropy > 3.5:
            findings.append("The domain has an unusual character pattern.")
            score += 10

    if main_domain.startswith("xn--"):
        findings.append("The domain uses Punycode encoding.")
        score += 15

    return score, findings

# --------------------------------------------------
# MAIN URL ANALYSIS FUNCTION
# --------------------------------------------------

def analyze_url(user_input):

    url = (user_input or "").strip()

    issues = []
    checks = []
    risk_score = 0

    # --------------------------------------------------
    # STAGE 1: URL FORMAT VALIDATION
    # --------------------------------------------------

    if not url:
        return make_result(
            url, "", 0, "Invalid",
            ["Please enter a URL."],
            False, checks
        )

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            raise ValueError

        if not parsed.hostname:
            raise ValueError

        domain = parsed.hostname.lower().strip(".")

        if not domain:
            raise ValueError

    except (ValueError, TypeError):
        return make_result(
            url, "", 0, "Invalid",
            ["The URL format is invalid."],
            False, checks
        )

    checks.append({
        "stage": "URL Format Validation",
        "status": "Passed",
        "details": "The URL has a valid HTTP or HTTPS format."
    })

    # --------------------------------------------------
    # STAGE 2: DOMAIN VALIDATION
    # --------------------------------------------------

    if len(domain) > 253:
        return make_result(
            url, domain, 0, "Invalid",
            ["The domain name is too long."],
            False, checks
        )

    if is_ip_address(domain):
        issues.append("The URL uses a direct IP address instead of a domain.")
        risk_score += 15

    else:
        labels = domain.split(".")

        if len(labels) < 2:
            return make_result(
                url, domain, 0, "Invalid",
                ["The domain does not contain a valid domain extension."],
                False, checks
            )

        valid_domain = True

        for label in labels:
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
            ):
                valid_domain = False
                break

        if not valid_domain:
            return make_result(
                url, domain, 0, "Invalid",
                ["The domain name contains invalid characters or formatting."],
                False, checks
            )

    checks.append({
        "stage": "Domain Validation",
        "status": "Passed",
        "details": "The domain structure is valid."
    })

    # --------------------------------------------------
    # STAGE 3: DNS / IP ADDRESS VERIFICATION
    # --------------------------------------------------

    if is_ip_address(domain):
        dns_success = True
        ip_addresses = [domain]
    else:
        dns_success, ip_addresses = resolve_domain(domain)

    if not dns_success:
        issues.append(
            "The domain could not be resolved to an IP address. "
            "Analysis stopped because the website could not be reached through DNS."
        )

        checks.append({
            "stage": "DNS Verification",
            "status": "Failed",
            "details": "No IP address could be resolved for this domain."
        })

        return make_result(
            url,
            domain,
            0,
            "Unreachable",
            issues,
            False,
            checks
        )

    checks.append({
        "stage": "DNS Verification",
        "status": "Passed",
        "details": "Domain resolved to: " + ", ".join(ip_addresses)
    })

    # --------------------------------------------------
    # STAGE 4: HTTPS AND SSL CERTIFICATE
    # --------------------------------------------------

    if parsed.scheme == "https":

        ssl_valid, ssl_message = check_ssl_certificate(domain)

        if ssl_valid:
            checks.append({
                "stage": "HTTPS and SSL Certificate",
                "status": "Passed",
                "details": ssl_message
            })

        else:
            risk_score += 35
            issues.append(ssl_message)

            checks.append({
                "stage": "HTTPS and SSL Certificate",
                "status": "Warning",
                "details": ssl_message
            })

    else:
        risk_score += 20

        issues.append(
            "The website uses HTTP instead of HTTPS. "
            "The connection is not protected by HTTPS."
        )

        checks.append({
            "stage": "HTTPS and SSL Certificate",
            "status": "Warning",
            "details": "The URL uses HTTP, not HTTPS."
        })

    # --------------------------------------------------
    # STAGE 5: SUSPICIOUS URL AND DOMAIN INDICATORS
    # --------------------------------------------------

    suspicious_findings = []
    suspicious_score = 0

    full_url_lower = url.lower()

    # Suspicious words
    for word in SUSPICIOUS_WORDS:
        if word in full_url_lower:
            suspicious_findings.append(
                "Suspicious keyword found: " + word
            )
            suspicious_score += 5

    # URL length
    if len(url) > 100:
        suspicious_findings.append(
            "The URL is unusually long."
        )
        suspicious_score += 10

    # @ symbol
    if "@" in url:
        suspicious_findings.append(
            "The URL contains an @ symbol, which can hide the actual destination."
        )
        suspicious_score += 15

    # Excessive subdomains
    if len(domain.split(".")) >= 5:
        suspicious_findings.append(
            "The domain contains an unusually large number of subdomains."
        )
        suspicious_score += 10

    # Percent encoding
    if url.count("%") >= 3:
        suspicious_findings.append(
            "The URL contains repeated encoded characters."
        )
        suspicious_score += 10

    # Redirect parameters
    query_parameters = parse_qs(parsed.query)

    for parameter in REDIRECT_PARAMETERS:
        if parameter in query_parameters:
            suspicious_findings.append(
                "The URL contains a redirect-related parameter: "
                + parameter
            )
            suspicious_score += 10
            break

    # Domain pattern
    pattern_score, pattern_findings = check_domain_pattern(domain)

    suspicious_score += pattern_score
    suspicious_findings.extend(pattern_findings)

    # Possible brand impersonation
    main_domain = domain.split(".")[0]

    for brand in KNOWN_BRANDS:
        if brand in main_domain and main_domain != brand:
            suspicious_findings.append(
                "The domain contains the name of a known brand "
                "but is not an exact brand domain."
            )
            suspicious_score += 15
            break

    risk_score += suspicious_score

    if suspicious_findings:
        issues.extend(suspicious_findings)

        checks.append({
            "stage": "Suspicious URL Indicators",
            "status": "Warning",
            "details": " ".join(suspicious_findings)
        })

    else:
        checks.append({
            "stage": "Suspicious URL Indicators",
            "status": "Passed",
            "details": "No configured suspicious URL indicators were found."
        })

    # --------------------------------------------------
    # STAGE 6: THREAT REPUTATION
    # --------------------------------------------------

    # No external API is used.
    # Therefore, threat database reputation is NOT verified.

    checks.append({
        "stage": "Threat Reputation",
        "status": "Not checked",
        "details": (
            "No external threat-intelligence API is configured. "
            "This URL has not been checked against Google's or another "
            "provider's malicious URL database."
        )
    })

    # --------------------------------------------------
    # STAGE 7: RISK SCORE AND FINAL CLASSIFICATION
    # --------------------------------------------------

    risk_score = min(risk_score, 100)

    if risk_score <= 15:
        status = "Safe"
    elif risk_score <= 40:
        status = "Suspicious"
    else:
        status = "Dangerous"

    if not issues:
        issues.append(
            "No suspicious indicators were detected by the configured checks. "
            "This does not guarantee that the website is safe."
        )

    checks.append({
        "stage": "Risk Score Calculation",
        "status": "Completed",
        "details": (
            "Final risk score: "
            + str(risk_score)
            + "/100. Classification: "
            + status
            + "."
        )
    })

    return make_result(
        url,
        domain,
        risk_score,
        status,
        issues,
        True,
        checks
    )