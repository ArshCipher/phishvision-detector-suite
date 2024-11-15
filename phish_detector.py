import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import math
import requests
import pickle
import os
import argparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier, callback
from flask import Flask, request, render_template, jsonify
import logging
from datetime import datetime
import tldextract
import ssl
import socket
import OpenSSL
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
import seaborn as sns
import sqlite3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import hashlib
import time
import urllib3

# Require python-whois
try:
    import whois
except ImportError:
    raise ImportError("Install 'python-whois' via pip: pip install python-whois")

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# SQLite setup
DB_FILE = "phish_log.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                label TEXT,
                probability REAL,
                timestamp TEXT
            )
        """)
        conn.commit()

# Common brands
BRANDS = ['paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft', 'bankofamerica', 'chase', 'wellsfargo']
KEYWORDS = ['login', 'password', 'verify', 'secure', 'account', 'signin', 'update']
PROBLEMATIC_TLDS = ['.sbs', '.xyz', '.icu', '.top', '.cfd', '.rest', '.win', '.shop', '.es', '.ru', '.de']
FREE_HOSTING_DOMAINS = [
    'firebaseapp.com', 'web.app', 'vercel.app', 'weebly.com', 'weeblysite.com',
    'glitch.me', 'square.site', 'wixsite.com', 'godaddysites.com', 'canva.site',
    'webflow.io', 'carrd.co', 'bubble.io', 'github.io', 'pages.dev', 'netlify.app',
    'gitbook.io', 'framer.app', 'does-it.net', 'blogspot.com', 'myvnc.com', 'hoster-test.ru'
]
ERROR_PRONE_HOSTS = [
    'docs.google.com', 's3.amazonaws.com', 'r2.dev', 'backblazeb2.com',
    'jotform.com', 'wemailtrack.com'
]

# Persistent cache for network calls
def load_cache(cache_file='cache.pkl'):
    return pickle.load(open(cache_file, 'rb')) if os.path.exists(cache_file) else {}

def save_cache(cache, cache_file='cache.pkl'):
    with open(cache_file, 'wb') as f:
        pickle.dump(cache, f)

cache = load_cache()

def cached_network_call(key, func):
    if key not in cache:
        cache[key] = func()
        save_cache(cache)
    return cache[key]

# Check if hostname resolves
def is_hostname_valid(hostname):
    if not hostname:
        return False
    dns_key = hashlib.md5(f"dns_{hostname}".encode()).hexdigest()
    def check_dns():
        try:
            socket.getaddrinfo(hostname, 80, proto=socket.IPPROTO_TCP, family=socket.AF_INET)
            return True
        except socket.gaierror:
            return False
    return cached_network_call(dns_key, check_dns)

# Track failed hosts
failed_hosts = set()
failed_whois_hosts = set()

# Feature extraction
def extract_features(url):
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or ''
        path = parsed_url.path or ''
        query = parsed_url.query or ''
        
        # Entropy
        def entropy(s):
            if not s:
                return 0
            p, l = {}, len(s)
            for c in s:
                p[c] = p.get(c, 0) + 1 / l
            return -sum(p[c] * math.log2(p[c]) for c in p)
        
        # TLD
        ext = tldextract.extract(url)
        tld = ext.suffix
        
        # WHOIS
        domain_age = -1
        has_whois = 0
        if is_hostname_valid(hostname):
            # Skip IPs and invalid domains
            if not hostname or re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                logger.debug(f"Skipping WHOIS for invalid/IP hostname: {hostname}")
                has_whois = 0
            else:
                # Extract base domain
                whois_domain = f"{ext.domain}.{ext.suffix}".lower()
                base_domain = whois_domain
                if not ext.domain or not ext.suffix:
                    logger.debug(f"Skipping WHOIS for invalid domain: {hostname}")
                    has_whois = 0
                # Skip free hosting, problematic TLDs, or failed hosts
                elif (any(hostname.endswith(free_domain) for free_domain in FREE_HOSTING_DOMAINS) or
                      tld in PROBLEMATIC_TLDS or
                      base_domain in failed_whois_hosts):
                    logger.debug(f"Skipping WHOIS for {hostname} (free hosting, problematic TLD, or previously failed)")
                    has_whois = 0
                else:
                    whois_key = hashlib.md5(f"whois_{whois_domain}".encode()).hexdigest()
                    try:
                        def fetch_whois():
                            time.sleep(0.1)  # Rate limit
                            socket.setdefaulttimeout(3)
                            w = whois.whois(whois_domain)
                            creation_date = w.creation_date
                            if isinstance(creation_date, list):
                                creation_date = creation_date[0]
                            return creation_date
                        creation_date = cached_network_call(whois_key, fetch_whois)
                        if creation_date:
                            domain_age = (datetime.now() - creation_date).days
                            has_whois = 1
                        else:
                            if base_domain not in failed_whois_hosts:
                                logger.debug(f"No WHOIS data for {whois_domain} - likely unregistered")
                                failed_whois_hosts.add(base_domain)
                    except socket.error as e:
                        if base_domain not in failed_whois_hosts:
                            logger.debug(f"WHOIS socket error for {whois_domain}: {e}")
                            failed_whois_hosts.add(base_domain)
                    except Exception as e:
                        if base_domain not in failed_whois_hosts:
                            logger.debug(f"WHOIS error for {whois_domain}: {e}")
                            failed_whois_hosts.add(base_domain)
                    finally:
                        socket.setdefaulttimeout(None)
        else:
            logger.debug(f"Skipping WHOIS for unresolvable hostname: {hostname}")
        
        # SSL
        has_valid_ssl = 0
        if parsed_url.scheme == 'https' and is_hostname_valid(hostname):
            ssl_key = hashlib.md5(f"ssl_{hostname}".encode()).hexdigest()
            try:
                def fetch_ssl():
                    cert = ssl.get_server_certificate((hostname, 443))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    not_after = datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
                    return 1 if not_after > datetime.now() else 0
                has_valid_ssl = cached_network_call(ssl_key, fetch_ssl)
            except Exception as e:
                logger.debug(f"SSL check failed for {hostname}: {e}")
        else:
            logger.debug(f"Skipping SSL for {hostname} (unresolvable or not HTTPS)")
        
        # Content
        num_keywords = 0
        content_entropy = 0
        if len(url) > 500:
            logger.debug(f"Skipping content fetch for long URL: {url[:50]}...")
        elif is_hostname_valid(hostname) and hostname not in failed_hosts and tld not in PROBLEMATIC_TLDS and not any(hostname.endswith(h) for h in ERROR_PRONE_HOSTS):
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                response = requests.get(url, timeout=(0.3, 0.7), headers=headers, allow_redirects=True, verify=False)
                status_code = response.status_code
                content_type = response.headers.get('Content-Type', '').lower()
                is_html = 'text/html' in content_type and response.text.strip().startswith(('<!DOCTYPE', '<html'))
                if status_code == 200 and is_html:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    text = soup.get_text().lower()
                    num_keywords = sum(text.count(kw) for kw in KEYWORDS)
                    content_entropy = entropy(text[:1000])
                elif status_code in (403, 404, 401):
                    if hostname not in failed_hosts:
                        logger.debug(f"URL {url} returned status {status_code} - treating as non-HTML response")
                        failed_hosts.add(hostname)
                elif status_code == 503:
                    if hostname not in failed_hosts and tld not in PROBLEMATIC_TLDS:
                        logger.info(f"URL {url} returned status 503 - retrying once")
                        time.sleep(0.3)
                        try:
                            response = requests.get(url, timeout=(0.3, 0.7), headers=headers, allow_redirects=True, verify=False)
                            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', '').lower():
                                soup = BeautifulSoup(response.text, 'html.parser')
                                text = soup.get_text().lower()
                                num_keywords = sum(text.count(kw) for kw in KEYWORDS)
                                content_entropy = entropy(text[:1000])
                            else:
                                logger.info(f"URL {url} retry failed - treating as non-HTML response")
                                failed_hosts.add(hostname)
                        except:
                            logger.info(f"URL {url} retry failed - treating as non-HTML response")
                            failed_hosts.add(hostname)
                    else:
                        logger.debug(f"URL {url} returned status 503 - already failed or problematic TLD")
                else:
                    logger.debug(f"URL {url} returned status {status_code} with Content-Type '{content_type}'")
            except requests.exceptions.Timeout:
                logger.debug(f"Timeout fetching content for {url}")
            except requests.exceptions.ConnectionError as e:
                logger.debug(f"Connection error for {url}: {e}")
            except Exception as e:
                logger.debug(f"Unexpected error fetching content for {url}: {e}")
        else:
            logger.debug(f"Skipping content fetch for {hostname} (unresolvable, failed, problematic TLD, or error-prone host)")
        
        features = {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_slashes': url.count('/'),
            'num_hyphens': url.count('-'),
            'num_at': url.count('@'),
            'num_hash': url.count('#'),
            'num_query_params': query.count('&') + (1 if query else 0),
            'has_https': 1 if parsed_url.scheme == 'https' else 0,
            'subdomain_count': len(ext.subdomain.split('.')) if ext.subdomain else 0,
            'has_ip': 1 if hostname and re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) else 0,
            'num_digits': sum(c.isdigit() for c in url),
            'num_special': sum(1 for c in url if not c.isalnum() and c not in '/.'),
            'hostname_entropy': entropy(hostname),
            'has_brand': 1 if any(brand in hostname.lower() for brand in BRANDS) else 0,
            'tld_length': len(tld),
            'path_depth': len([x for x in path.split('/') if x]),
            'has_login': 1 if any(x in url.lower() for x in ['login', 'signin']) else 0,
            'has_verify': 1 if any(x in url.lower() for x in ['verify', 'secure']) else 0,
            'domain_age_days': domain_age,
            'has_valid_ssl': has_valid_ssl,
            'num_keywords': num_keywords,
            'content_entropy': content_entropy,
            'has_whois': has_whois
        }
        return features
    except Exception as e:
        logger.error(f"Error parsing URL {url}: {e}")
        # Return partial features
        return {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_slashes': url.count('/'),
            'num_hyphens': url.count('-'),
            'num_at': url.count('@'),
            'num_hash': url.count('#'),
            'num_query_params': query.count('&') + (1 if query else 0),
            'has_https': 1 if url.lower().startswith('https://') else 0,
            'subdomain_count': 0,
            'has_ip': 0,
            'num_digits': sum(c.isdigit() for c in url),
            'num_special': sum(1 for c in url if not c.isalnum() and c not in '/.'),
            'hostname_entropy': 0,
            'has_brand': 0,
            'tld_length': 0,
            'path_depth': len([x for x in path.split('/') if x]),
            'has_login': 1 if any(x in url.lower() for x in ['login', 'signin']) else 0,
            'has_verify': 1 if any(x in url.lower() for x in ['verify', 'secure']) else 0,
            'domain_age_days': -1,
            'has_valid_ssl': 0,
            'num_keywords': 0,
            'content_entropy': 0,
            'has_whois': 0
        }

# Simulate dataset
def create_dataset():
    data = []
    # Phishing (5,000)
    for i in range(2500):
        data.append((f'http://secure-paypal{i}.xyz/verify', 1))
        data.append((f'http://192.168.1.{i}/login', 1))
    # Legit (5,000)
    for i in range(2500):
        data.append((f'https://www.google.com/search?q={i}', 0))
        data.append((f'https://amazon.co.uk/product{i}', 0))
    
    urls, labels = zip(*data)
    features = []
    valid_labels = []
    
    def process_url(url, label):
        feat = extract_features(url)
        return feat, label if feat else None
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_url = {executor.submit(process_url, url, label): url for url, label in zip(urls, labels)}
        for future in tqdm(as_completed(future_to_url), total=len(urls), desc="Extracting features"):
            feat, lbl = future.result()
            if feat and lbl is not None:
                features.append(list(feat.values()))
                valid_labels.append(lbl)
    
    return np.array(features), np.array(valid_labels)

# Load real dataset
def load_real_dataset(phish_file='online-valid.csv', legit_file='legit_urls.csv'):
    try:
        phish_df = pd.read_csv(phish_file)
        phish_urls = phish_df['url'].head(5000).tolist()
        phish_labels = [1] * len(phish_urls)
    except:
        logger.warning("PhishTank data missing, using fallback...")
        phish_urls = [f'http://fake{i}.com' for i in range(5000)]
        phish_labels = [1] * 5000
    
    try:
        legit_df = pd.read_csv(legit_file)
        legit_urls = legit_df['url'].head(5000).tolist()
        legit_labels = [0] * len(legit_urls)
    except:
        logger.warning("Legit data missing, using fallback...")
        legit_urls = [f'https://site{i}.com' for i in range(5000)]
        legit_labels = [0] * 5000
    
    urls = phish_urls + legit_urls
    labels = phish_labels + legit_labels
    
    features = []
    valid_labels = []
    
    def process_url(url, label):
        feat = extract_features(url)
        return feat, label if feat else None
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_url = {executor.submit(process_url, url, label): url for url, label in zip(urls, labels)}
        for future in tqdm(as_completed(future_to_url), total=len(urls), desc="Extracting features"):
            feat, lbl = future.result()
            if feat and lbl is not None:
                features.append(list(feat.values()))
                valid_labels.append(lbl)
    
    X = np.array(features)
    y = np.array(valid_labels)
    np.save('features_X.npy', X)
    np.save('features_y.npy', y)
    return X, y

# Train model
def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = XGBClassifier(n_estimators=200, random_state=42, eval_metric='logloss', verbosity=1)
    logger.info("Starting model training...")
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        callbacks=[
            callback.EarlyStopping(
                rounds=10,
                save_best=True,
                metric_name='logloss',
                data_name='validation_0'
            )
        ],
        verbose=True
    )
    
    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    logger.info(f"Model Accuracy: {acc:.2f}")
    logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
    
    # Feature importance
    importance = pd.DataFrame({
        'feature': [
            'url_length', 'num_dots', 'num_slashes', 'num_hyphens', 'num_at', 'num_hash',
            'num_query_params', 'has_https', 'subdomain_count', 'has_ip', 'num_digits',
            'num_special', 'hostname_entropy', 'has_brand', 'tld_length', 'path_depth',
            'has_login', 'has_verify', 'domain_age_days', 'has_valid_ssl', 'num_keywords',
            'content_entropy', 'has_whois'
        ],
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    logger.info(f"Feature Importance:\n{importance}")
    
    # Plot importance
    plt.figure(figsize=(10, 6))
    sns.barplot(x='importance', y='feature', data=importance)
    plt.title('Feature Importance')
    plt.tight_layout()
    plt.savefig('feature_importance.png')
    logger.info("Feature importance plot saved to feature_importance.png")
    
    # Save model
    with open('phish_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    return model

# Load or train model
def load_model():
    if os.path.exists('phish_model.pkl'):
        with open('phish_model.pkl', 'rb') as f:
            return pickle.load(f)
    if os.path.exists('features_X.npy') and os.path.exists('features_y.npy'):
        logger.info("Loading cached features...")
        X = np.load('features_X.npy')
        y = np.load('features_y.npy')
    else:
        try:
            X, y = load_real_dataset()
        except:
            logger.warning("Falling back to simulated dataset...")
            X, y = create_dataset()
    return train_model(X, y)

# Predict single URL
def predict_url(url, model):
    try:
        feat = extract_features(url)
        if not feat:
            return {'label': 'Invalid URL', 'probability': 0.0}
        
        features = np.array([list(feat.values())])
        pred = model.predict(features)[0]
        prob = model.predict_proba(features)[0][1]
        
        result = {'label': 'Phishing' if pred == 1 else 'Legitimate', 'probability': prob}
        
        # Log to SQLite
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO predictions (url, label, probability, timestamp) VALUES (?, ?, ?, ?)",
                (url, result['label'], result['probability'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
        
        return result
    except Exception as e:
        logger.error(f"Error processing URL {url}: {e}")
        return {'label': 'Invalid URL', 'probability': 0.0}

# Save results
def save_results(urls, results, format='csv'):
    df = pd.DataFrame([
        {'url': url, 'label': res['label'], 'phishing_probability': res['probability']}
        for url, res in zip(urls, results)
    ])
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if format == 'csv':
        filename = f'phish_results_{timestamp}.csv'
        df.to_csv(filename, index=False)
    else:
        filename = f'phish_results_{timestamp}.json'
        df.to_json(filename, orient='records', indent=4)
    logger.info(f"Results saved to {filename}")

# Flask app
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    model = load_model()
    result = None
    url = None
    if request.method == 'POST':
        url = request.form['url']
        result = predict_url(url, model)
    return render_template('index.html', result=result, url=url)

@app.route('/api/predict', methods=['POST'])
def api_predict():
    model = load_model()
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL required'}), 400
    result = predict_url(url, model)
    return jsonify(result)

# Main CLI
def main():
    init_db()
    parser = argparse.ArgumentParser(description="Ultimate Phishing URL Detector")
    parser.add_argument('urls', nargs='*', help="URLs to check")
    parser.add_argument('--train', action='store_true', help="Force retrain model")
    parser.add_argument('--web', action='store_true', help="Run web interface")
    parser.add_argument('--api', action='store_true', help="Run API only")
    parser.add_argument('--format', choices=['csv', 'json'], default='csv', help="Output format")
    args = parser.parse_args()
    
    if args.web or args.api:
        logger.info("Starting Flask server...")
        app.run(debug=False, host='0.0.0.0', port=5000)
        return
    
    if args.train or not os.path.exists('phish_model.pkl'):
        logger.info("Training new model...")
        if os.path.exists('features_X.npy') and os.path.exists('features_y.npy'):
            logger.info("Loading cached features...")
            X = np.load('features_X.npy')
            y = np.load('features_y.npy')
        else:
            try:
                X, y = load_real_dataset()
            except:
                logger.warning("Falling back to simulated dataset...")
                X, y = create_dataset()
        model = train_model(X, y)
    else:
        model = load_model()
    
    if args.urls:
        results = []
        for url in args.urls:
            res = predict_url(url, model)
            results.append(res)
            logger.info(f"URL: {url}\nResult: {res['label']} (Phishing Prob: {res['probability']:.2f})")
        save_results(args.urls, results, args.format)
    else:
        # Interactive mode
        while True:
            url = input("Enter URL to check (or 'quit' to exit): ")
            if url.lower() == 'quit':
                break
            res = predict_url(url, model)
            logger.info(f"Result: {res['label']} (Phishing Prob: {res['probability']:.2f})")

if __name__ == "__main__":
    main()