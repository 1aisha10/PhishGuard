
import os
os.environ['HF_HOME'] = 'D:/huggingface_cache'
from flask import Flask, render_template, request
import pickle
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import math
import socket
import ssl
import dns.resolver
import whois
from datetime import datetime
import requests
from ipwhois import IPWhois
from transformers import pipeline
import base64
import time
from dotenv import load_dotenv
load_dotenv()
from groq import Groq
app = Flask(__name__)

# Load model and feature columns
model = pickle.load(open("phishing_model.pkl", "rb"))
feature_columns = pickle.load(open("feature_columns.pkl", "rb"))

# Load HuggingFace model
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
   print("Loading HuggingFace model...")
   hf_model = pipeline("text-classification", model="elftsdmr/malware-url-detect")
   print("HuggingFace model loaded!")
else:
    hf_model = None


# ==============================
# API KEYS
# ==============================

GOOGLE_API_KEY     = os.getenv('GOOGLE_API_KEY')
APIFLASH_KEY       = os.getenv('APIFLASH_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GROQ_API_KEY       =os.getenv('GROQ_API_KEY')
client = Groq(api_key=GROQ_API_KEY)


scan_cache = {}

def get_cached_or_scan(url, fn, *args):
    key = f"{fn.__name__}:{url}"
    if key not in scan_cache:
        scan_cache[key] = fn(*args)
    return scan_cache[key]

# ==============================
# GOOGLE SAFE BROWSING
# ==============================

def check_google_safe_browsing(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=payload)
        data = response.json()
        if "matches" in data:
            return True
        return False
    except:
        return False

# ==============================
# VIRUSTOTAL
# ==============================

def check_virustotal(url):
    vt_result = {
        'total':      0,
        'malicious':  0,
        'suspicious': 0,
        'clean':      0,
        'error':      False,
        'error_msg': None
    }
    try:
        # Submit URL
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data    = {"url": url}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data=data
        )
        if response.status_code != 200:
            vt_result['error'] = True
            return vt_result

        analysis_id = response.json()['data']['id']

        # Wait for analysis
        time.sleep(2)

        # Get results
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        stats = result.json()['data']['attributes']['stats']

        vt_result['malicious']  = stats.get('malicious', 0)
        vt_result['suspicious'] = stats.get('suspicious', 0)
        vt_result['clean']      = stats.get('undetected', 0) + stats.get('harmless', 0)
        vt_result['total']      = vt_result['malicious'] + vt_result['suspicious'] + vt_result['clean']

    except Exception as e:
        vt_result['error'] = True
        vt_result['error_msg'] = str(e)
        return vt_result

    return vt_result

# ==============================
# SCREENSHOT
# ==============================

def get_screenshot_url(url):
    try:
        return (
            f"https://api.apiflash.com/v1/urltoimage"
            f"?access_key={APIFLASH_KEY}"
            f"&url={url}"
            f"&width=1280"
            f"&height=720"
            f"&format=jpeg"
            f"&quality=80"
            f"&fresh=true"
            f"&response_type=image"
        )
    except:
        return None

# ==============================
# IP + LOCATION + HOSTING
# ==============================

def get_ip_info(hostname):
    info = {
        'ip': None, 'country': None,
        'city': None, 'hosting_provider': None, 'asn': None
    }
    try:
        ip = socket.gethostbyname(hostname)
        info['ip'] = ip
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        info['country']          = result.get('asn_country_code', 'Unknown')
        info['hosting_provider'] = result.get('asn_description', 'Unknown')
        info['asn']              = result.get('asn', 'Unknown')
        info['city']             = result.get('network', {}).get('name', 'Unknown')
    except:
        pass
    return info

# ==============================
# CERTIFICATE DETAILS
# ==============================

def get_certificate_info(hostname):
    info = {'issuer': None, 'valid_from': None, 'valid_to': None, 'is_valid': False}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            info['issuer']     = issuer.get('organizationName', 'Unknown')
            info['valid_from'] = cert['notBefore']
            info['valid_to']   = cert['notAfter']
            info['is_valid']   = True
    except:
        info['is_valid'] = False
    return info

# ==============================
# BRAND DETECTION
# ==============================

BRANDS = {
    'google': 'Google', 'youtube': 'YouTube', 'facebook': 'Facebook',
    'instagram': 'Instagram', 'twitter': 'Twitter', 'microsoft': 'Microsoft',
    'apple': 'Apple', 'amazon': 'Amazon', 'paypal': 'PayPal',
    'netflix': 'Netflix', 'linkedin': 'LinkedIn', 'github': 'GitHub',
    'whatsapp': 'WhatsApp', 'dropbox': 'Dropbox', 'spotify': 'Spotify',
    'ebay': 'eBay', 'walmart': 'Walmart', 'adobe': 'Adobe',
    'wikipedia': 'Wikipedia', 'reddit': 'Reddit'
}

def detect_brand(url, hostname):
    domain = hostname.replace('www.', '')
    if is_trusted_domain(hostname):
        return None  # real domain, not impersonation
    url_lower = url.lower()
    for key, name in BRANDS.items():
        if key in url_lower:
            return name  # brand word in URL but not real domain = impersonation
    return None


def calculate_final_verdict(url, hostname, ml_prediction, ml_confidence,
                             hf_is_phishing, hf_confidence,
                             is_dangerous, vt_result, brand, cert_info):

    reasons  = []
    warnings = []
    score    = 0  # 0 = safe, 100 = phishing

    # Google Safe Browsing — highest weight
    if is_dangerous:
        score += 40
        reasons.append("🚨 Flagged by Google Safe Browsing")

    # VirusTotal
    if not vt_result['error'] and vt_result['total'] > 0:
        malicious_pct = vt_result['malicious'] / vt_result['total'] * 100
        if malicious_pct > 20:
            score += 25
            reasons.append(f"🦠 {vt_result['malicious']} antivirus engines flagged as malicious")
        elif malicious_pct > 5:
            score += 10
            warnings.append(f"⚠️ {vt_result['malicious']} engines flagged as suspicious")

    # ML Model
    if ml_prediction == 1:
        score += 20
        reasons.append(f"🤖 ML model detected phishing ({ml_confidence}% confidence)")
    
    # HuggingFace
    if hf_is_phishing:
        score += 15
        reasons.append(f"🧠 HuggingFace AI detected malware ({hf_confidence}% confidence)")

    # URL feature checks
    parsed = urlparse(url)
    path   = parsed.path.lower()
    domain = hostname.replace('www.', '')

    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
    tld = domain.split('.')[-1] if '.' in domain else ''
    if tld in suspicious_tlds:
        score += 10
        reasons.append(f"⚠️ Suspicious TLD (.{tld}) commonly used in phishing")

    if any(w in url.lower() for w in ['login', 'signin', 'verify', 'secure', 'account', 'update', 'bank']):
        score += 5
        warnings.append("⚠️ URL contains sensitive keywords (login/verify/secure)")

    if re.search(r'\d+\.\d+\.\d+\.\d+', hostname):
        score += 10
        reasons.append("🚨 URL uses raw IP address instead of domain name")

    if url.count('.') > 4:
        score += 5
        warnings.append("⚠️ Unusually high number of dots in URL (subdomain abuse)")

    if not cert_info['is_valid']:
        score += 5
        warnings.append("⚠️ No valid SSL certificate found")

    if brand:
        score += 10
        reasons.append(f"🚨 Impersonating {brand} brand on non-official domain")

    # typosquatting check
    common = ['google','paypal','amazon','facebook','microsoft','apple','netflix']
    for legit in common:
        for c in domain:
            test = domain.replace(c, '')
            if test == legit or legit in domain and domain != legit + '.com':
                warnings.append(f"⚠️ Domain may be typosquatting {legit}.com")
                score += 8
                break

    # Final verdict
    score = min(score, 100)
    if score >= 50:
        final_label = 'PHISHING'
        final_prediction = 1
    else:
        final_label = 'SAFE'
        final_prediction = 0

    final_confidence = score if final_prediction == 1 else (100 - score)

    return {
        'prediction':        final_prediction,
        'label':             final_label,
        'confidence':        final_confidence,
        'score':             score,
        'reasons':           reasons,
        'warnings':          warnings
    }
def ask_ai_about_url(question, result):
    try:
        context = f"""
        URL: {result['url']}
        Final Verdict: {result['label']}
        Confidence: {result['confidence']}%
        Reasons: {', '.join(result['reasons'])}
        Warnings: {', '.join(result['warnings'])}
        VirusTotal: {result['vt']}
        """

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity assistant helping users understand phishing risks and phishing URLs."
                },
                {
                    "role": "user",
                    "content": context + "\n\nUser Question: " + question
                }
            ],
            temperature=0.3,
            max_tokens=500
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"Groq AI Error: {str(e)}"

# ==============================
# TRUSTED DOMAINS
# ==============================

TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'wikipedia.org', 'github.com', 'linkedin.com', 'netflix.com',
    'reddit.com', 'yahoo.com', 'bing.com', 'whatsapp.com',
    'python.org', 'stackoverflow.com', 'twitch.tv', 'adobe.com',
    'dropbox.com', 'paypal.com', 'ebay.com', 'walmart.com',
    'spotify.com', 'tiktok.com', 'pinterest.com', 'tumblr.com'
]

def is_trusted_domain(hostname):
    domain = hostname.replace('www.', '')
    return any(domain == t or domain.endswith('.' + t) for t in TRUSTED_DOMAINS)

# ==============================
# HUGGINGFACE MODEL CHECK
# ==============================

def check_hf_model(url):
    try:
        result = hf_model(url)[0]
        print("HF raw result:", result)
        label = result['label'].lower()
        score = round(result['score'] * 100, 2)
        is_phishing = 'phish' in label or 'malicious' in label or 'bad' in label or 'malware' in label
        return is_phishing, score
    except:
        return None, None

# ==============================
# FEATURE EXTRACTION FROM URL
# ==============================

def get_entropy(text):
    if not text:
        return 0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    domain = hostname.replace('www.', '')
    path = parsed.path or ''
    query = parsed.query or ''

    features['url_length']               = len(url)
    features['domain_length']            = len(domain)
    features['hostname_length']          = len(hostname)
    features['path_length']              = len(path)
    features['first_dir_length']         = len(path.split('/')[1]) if len(path.split('/')) > 1 else 0
    features['tld_length']               = len(domain.split('.')[-1]) if '.' in domain else 0
    features['tld_length_domain']        = len(domain.split('.')[-1]) if '.' in domain else 0
    features['url_depth']                = path.count('/')
    features['query_length']             = len(query)
    features['path_segments_count']      = len([x for x in path.split('/') if x])
    features['num_digits']               = sum(c.isdigit() for c in url)
    features['num_letters']              = sum(c.isalpha() for c in url)
    features['num_special_chars']        = sum(not c.isalnum() for c in url)
    features['num_dots']                 = url.count('.')
    features['num_hyphens']              = url.count('-')
    features['num_at']                   = url.count('@')
    features['num_percent']              = url.count('%')
    features['num_equals']               = url.count('=')
    features['num_question']             = url.count('?')
    features['num_ampersand']            = url.count('&')
    features['num_hash']                 = url.count('#')
    features['num_underscore']           = url.count('_')
    features['num_special']              = url.count('.') + url.count('-') + url.count('_')
    features['num_slash']                = url.count('/')
    features['num_params']               = len(query.split('&')) if query else 0
    features['entropy_url']              = get_entropy(url)
    features['entropy_hostname']         = get_entropy(hostname)
    features['entropy_domain']           = get_entropy(domain)
    features['entropy_path']             = get_entropy(path)
    features['query_entropy']            = get_entropy(query)
    features['ratio_digits']             = features['num_digits'] / len(url) if url else 0
    features['ratio_letters']            = features['num_letters'] / len(url) if url else 0
    features['ratio_special_chars']      = features['num_special_chars'] / len(url) if url else 0
    features['uppercase_ratio']          = sum(c.isupper() for c in url) / len(url) if url else 0
    features['lowercase_ratio']          = sum(c.islower() for c in url) / len(url) if url else 0
    features['is_ip_address']            = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) else 0
    features['starts_with_ip']           = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', hostname) else 0
    features['is_suspicious_tld']        = 1 if domain.split('.')[-1] in ['xyz','top','tk','ml','ga','cf','gq'] else 0
    features['uses_https']               = 1 if url.startswith('https') else 0
    features['has_www']                  = 1 if 'www.' in url else 0
    features['unusual_double_slash']     = 1 if url.count('//') > 1 else 0
    features['multiple_http']            = 1 if url.lower().count('http') > 1 else 0
    features['contains_port_number']     = 1 if re.search(r':\d{2,5}', hostname) else 0
    features['path_has_encoded_chars']   = 1 if '%' in path else 0
    features['query_has_base64']         = 1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', query) else 0
    features['contains_login']           = 1 if 'login' in url.lower() else 0
    features['contains_secure']          = 1 if 'secure' in url.lower() else 0
    features['contains_verify']          = 1 if 'verify' in url.lower() else 0
    features['contains_account']         = 1 if 'account' in url.lower() else 0
    features['contains_update']          = 1 if 'update' in url.lower() else 0
    features['contains_bank']            = 1 if 'bank' in url.lower() else 0
    features['contains_cloud']           = 1 if 'cloud' in url.lower() else 0
    features['contains_brand']           = 1 if any(b in url.lower() for b in ['paypal','google','amazon','apple','microsoft','facebook']) else 0
    features['query_key_count']          = len(re.findall(r'[\?&](\w+)=', query))
    features['query_value_length_avg']   = np.mean([len(v) for v in re.findall(r'=([^&]*)', query)]) if query else 0

    features['success']                  = 0
    features['dns_resolves']             = 0
    features['has_mx_record']            = 0
    features['has_txt_record']           = 0
    features['has_ns_record']            = 0
    features['ttl_value']                = 0
    features['ip_count']                 = 0
    features['cname_count']              = 0
    features['resolves_to_private_ip']   = 0
    features['whois_success']            = 0
    features['domain_age_days']          = 0
    features['expiration_days']          = 0
    features['creation_year']            = 0
    features['domain_is_recent']         = 0
    features['domain_registered_before_2020'] = 0
    features['registrar_valid']          = 0
    features['name_servers_count']       = 0
    features['is_privacy_protected']     = 0
    features['whois_missing']            = 1

    df = pd.DataFrame([features])
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0
    df = df[feature_columns]
    return df

# ==============================
# LIVE DNS + WHOIS LOOKUP
# ==============================

def get_live_dns_features(hostname):
    features = {}
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        features['dns_resolves'] = 1
        features['ip_count']     = len(answers)
        features['success']      = 1
    except:
        features['dns_resolves'] = 0
        features['ip_count']     = 0
        features['success']      = 0

    try:
        dns.resolver.resolve(hostname, 'MX')
        features['has_mx_record'] = 1
    except:
        features['has_mx_record'] = 0

    try:
        dns.resolver.resolve(hostname, 'TXT')
        features['has_txt_record'] = 1
    except:
        features['has_txt_record'] = 0

    try:
        ns_answers = dns.resolver.resolve(hostname, 'NS')
        features['has_ns_record']      = 1
        features['name_servers_count'] = len(ns_answers)
    except:
        features['has_ns_record']      = 0
        features['name_servers_count'] = 0

    try:
        w = whois.whois(hostname)
        features['whois_success'] = 1
        features['whois_missing'] = 0
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.now() - creation).days
            features['domain_age_days']               = age
            features['creation_year']                 = creation.year
            features['domain_is_recent']              = 1 if age < 365 else 0
            features['domain_registered_before_2020'] = 1 if creation.year < 2020 else 0
        else:
            features['domain_age_days']               = 0
            features['creation_year']                 = 0
            features['domain_is_recent']              = 0
            features['domain_registered_before_2020'] = 0
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        features['expiration_days']      = (expiration - datetime.now()).days if expiration else 0
        features['registrar_valid']      = 1 if w.registrar else 0
        features['is_privacy_protected'] = 1 if w.emails and 'privacy' in str(w.emails).lower() else 0
    except:
        features['whois_success']                 = 0
        features['whois_missing']                 = 1
        features['domain_age_days']               = 0
        features['creation_year']                 = 0
        features['domain_is_recent']              = 0
        features['domain_registered_before_2020'] = 0
        features['expiration_days']               = 0
        features['registrar_valid']               = 0
        features['is_privacy_protected']          = 0

    features['ttl_value']              = 0
    features['cname_count']            = 0
    features['resolves_to_private_ip'] = 0
    return features

# ==============================
# ROUTES
# ==============================
@app.route('/')
def landing():
   return render_template('landing.html')
@app.route('/scan', methods=['GET', 'POST'])
def index():
    result = None
    url    = ''
    error  = None

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            error = "Please enter a URL."
        else:
            if not url.startswith('http'):
                url = 'http://' + url
            try:
                parsed   = urlparse(url)
                hostname = parsed.hostname or ''

                with ThreadPoolExecutor(max_workers=6) as executor:
                    f_ip  = executor.submit(get_cached_or_scan, url, get_ip_info, hostname)
                    f_cert = executor.submit(get_cached_or_scan, url, get_certificate_info, hostname)
                    f_vt  = executor.submit(get_cached_or_scan, url, check_virustotal, url)
                    f_hf  = executor.submit(get_cached_or_scan, url, check_hf_model, url)
                    f_gsb = executor.submit(get_cached_or_scan, url, check_google_safe_browsing, url)

                    ip_info                       = f_ip.result()
                    cert_info                     = f_cert.result()
                    vt_result                     = f_vt.result()
                    hf_is_phishing, hf_confidence = f_hf.result()
                    is_dangerous                  = f_gsb.result()

                brand      = detect_brand(url, hostname)
                tld        = hostname.split('.')[-1] if '.' in hostname else 'unknown'
                screenshot = get_screenshot_url(url)

                # Run ML model
                if not is_dangerous and not is_trusted_domain(hostname):
                    features_df = extract_features(url)
                    live = get_live_dns_features(hostname)
                    for key, val in live.items():
                        if key in features_df.columns:
                            features_df[key] = val
                    ml_prediction  = int(model.predict(features_df)[0])
                    ml_probability = model.predict_proba(features_df)[0]
                    ml_confidence  = round(max(ml_probability) * 100, 2)
                else:
                    ml_prediction = 1 if is_dangerous else 0
                    ml_confidence = 100 if is_dangerous else 99

                verdict = calculate_final_verdict(
                    url, hostname,
                    ml_prediction, ml_confidence,
                    hf_is_phishing, hf_confidence,
                    is_dangerous, vt_result, brand, cert_info
                )

                result = {
                    'prediction':  verdict['prediction'],
                    'label':       verdict['label'],
                    'confidence':  verdict['confidence'],
                    'score':       verdict['score'],
                    'reasons':     verdict['reasons'],
                    'warnings':    verdict['warnings'],
                    'url':         url,
                    'source':      'Combined AI Engines',
                    'ip_info':     ip_info,
                    'cert_info':   cert_info,
                    'brand':       brand,
                    'tld':         tld,
                    'screenshot':  screenshot,
                    'hf_phishing': hf_is_phishing,
                    'hf_score':    hf_confidence,
                    'vt':          vt_result
                }


            except Exception as e:
                error = f"Error processing URL: {str(e)}"

    return render_template('index.html', result=result, url=url, error=error)
@app.route('/ask_ai', methods=['POST'])
def ask_ai():
    question = request.form.get('question')
    result_data = request.form.get('result')

    if not question or not result_data:
        return {"answer": "Missing question or result"}

    import json
    result = json.loads(result_data)

    answer = ask_ai_about_url(question, result)

    return {"answer": answer}
if __name__ == '__main__':
    app.run(debug=True)