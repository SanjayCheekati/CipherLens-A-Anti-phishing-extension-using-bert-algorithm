#!/usr/bin/env python
"""
CipherLens Phishing URL Dataset Generator
-----------------------------------------
Generates a synthetic dataset of legitimate and phishing URLs for testing
"""

import os
import csv
import random
import argparse
import string
from datetime import datetime
from urllib.parse import urlparse

# Set random seed for reproducibility
random.seed(42)

# Constants for URL generation
TLD_LEGITIMATE = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.us', '.ca', '.uk']
TLD_SUSPICIOUS = ['.xyz', '.info', '.cc', '.biz', '.tk', '.ml', '.ga', '.cf', '.gq']

LEGITIMATE_DOMAINS = [
    'google', 'facebook', 'amazon', 'microsoft', 'apple', 'youtube', 'twitter', 
    'instagram', 'linkedin', 'github', 'reddit', 'netflix', 'spotify', 'paypal',
    'dropbox', 'adobe', 'slack', 'zoom', 'wordpress', 'shopify', 'ebay', 'airbnb',
    'uber', 'lyft', 'walmart', 'target', 'bestbuy', 'costco', 'fedex', 'ups',
    'usps', 'chase', 'bankofamerica', 'wellsfargo', 'citi', 'amex', 'discover'
]

LEGITIMATE_SUBDOMAINS = [
    'www', 'mail', 'drive', 'docs', 'login', 'account', 'secure', 'shop',
    'store', 'payments', 'pay', 'auth', 'my', 'support', 'help', 'signin',
    'accounts', 'security', 'developer', 'dev', 'api', 'blog', 'news'
]

PHISHING_TECHNIQUES = [
    'domain_typo', 'subdomain_confusion', 'homograph_attack', 
    'url_shortener', 'ip_address', 'excessive_subdirectories',
    'excessive_query_params', 'keyword_stuffing', 'suspicious_tld'
]

COMMON_PATHS = [
    '/login', '/signin', '/account', '/password-reset', '/verify', '/secure',
    '/checkout', '/payment', '/billing', '/update', '/confirm', '/validate',
    '/auth', '/dashboard', '/profile', '/settings'
]

def create_directory_if_not_exists(directory):
    """Create directory if it doesn't exist"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def generate_legitimate_url():
    """Generate a legitimate URL"""
    domain = random.choice(LEGITIMATE_DOMAINS)
    tld = random.choice(TLD_LEGITIMATE)
    
    # Sometimes add a subdomain
    if random.random() < 0.4:
        subdomain = random.choice(LEGITIMATE_SUBDOMAINS)
        domain = f"{subdomain}.{domain}"
    
    # Base URL
    url = f"https://{domain}{tld}"
    
    # Sometimes add a path
    if random.random() < 0.7:
        path = random.choice(COMMON_PATHS)
        url += path
        
        # Sometimes add subdirectories
        if random.random() < 0.3:
            subdirs = random.randint(1, 2)
            for _ in range(subdirs):
                subdir = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))
                path += f"/{subdir}"
            url += path
    
    # Sometimes add query parameters
    if random.random() < 0.4:
        params = []
        param_count = random.randint(1, 3)
        for _ in range(param_count):
            param_name = random.choice(['id', 'user', 'page', 'source', 'ref', 'campaign', 'utm_source', 'utm_medium'])
            param_value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(4, 10)))
            params.append(f"{param_name}={param_value}")
        url += f"?{'&'.join(params)}"
    
    # URL features
    features = {
        'hasHTTPS': 'https://' in url,
        'domainLength': len(urlparse(url).netloc),
        'numSubdomains': len(urlparse(url).netloc.split('.')) - 2 if len(urlparse(url).netloc.split('.')) > 2 else 0,
        'hasIPAddress': False,
        'hasSuspiciousTLD': False,
        'pathLength': len(urlparse(url).path),
        'numQueryParams': url.count('&') + (1 if '?' in url else 0),
        'hasAtSymbol': '@' in url,
        'hasDoubleSlash': '//' in urlparse(url).path,
        'hasLongURL': len(url) > 100,
        'hasManyDots': url.count('.') > 3,
        'hasURLShortener': False,
        'hasHexChars': any(c in url for c in '0123456789abcdef'),
        'hasExcessiveSubDirs': url.count('/') > 4,
    }
    
    return {
        'url': url,
        'is_phishing': False,
        'category': 'legitimate',
        'risk_level': 'safe',
        'features': features
    }

def generate_phishing_url():
    """Generate a phishing URL using various techniques"""
    technique = random.choice(PHISHING_TECHNIQUES)
    domain = random.choice(LEGITIMATE_DOMAINS)
    
    features = {
        'hasHTTPS': False,
        'domainLength': 0,
        'numSubdomains': 0,
        'hasIPAddress': False,
        'hasSuspiciousTLD': False,
        'pathLength': 0,
        'numQueryParams': 0,
        'hasAtSymbol': False,
        'hasDoubleSlash': False,
        'hasLongURL': False,
        'hasManyDots': False,
        'hasURLShortener': False,
        'hasHexChars': False,
        'hasExcessiveSubDirs': False,
    }
    
    if technique == 'domain_typo':
        # Typosquatting: misspell the domain
        chars = list(domain)
        pos = random.randint(0, len(domain) - 1)
        chars[pos] = random.choice(string.ascii_lowercase)
        domain = ''.join(chars)
        tld = random.choice(TLD_LEGITIMATE)
        url = f"http://{domain}{tld}{random.choice(COMMON_PATHS)}"
        features['hasHTTPS'] = False
    
    elif technique == 'subdomain_confusion':
        # Use the legitimate domain as a subdomain
        tld = random.choice(TLD_SUSPICIOUS)
        malicious_domain = ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))
        url = f"http://{domain}.{malicious_domain}{tld}{random.choice(COMMON_PATHS)}"
        features['numSubdomains'] = 1
        features['hasManyDots'] = True
    
    elif technique == 'homograph_attack':
        # Replace characters with similar-looking ones
        homographs = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 'l': '1'}
        chars = list(domain)
        replaced = False
        for i, char in enumerate(chars):
            if char in homographs and random.random() < 0.7:
                chars[i] = homographs[char]
                replaced = True
        if not replaced and 'o' in chars:
            chars[chars.index('o')] = '0'
        domain = ''.join(chars)
        tld = random.choice(TLD_LEGITIMATE)
        url = f"https://{domain}{tld}{random.choice(COMMON_PATHS)}"
        features['hasHTTPS'] = True
        features['hasHexChars'] = any(c in url for c in '0123456789abcdef')
    
    elif technique == 'url_shortener':
        # Fake URL shortener
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd']
        shortener = random.choice(shorteners)
        short_code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5, 8)))
        url = f"http://{shortener}/{short_code}"
        features['hasURLShortener'] = True
    
    elif technique == 'ip_address':
        # Use IP address instead of domain
        ip = '.'.join(str(random.randint(1, 255)) for _ in range(4))
        url = f"http://{ip}{random.choice(COMMON_PATHS)}"
        features['hasIPAddress'] = True
        features['hasHTTPS'] = False
    
    elif technique == 'excessive_subdirectories':
        # Use many subdirectories
        tld = random.choice(TLD_SUSPICIOUS)
        path = ''
        for _ in range(random.randint(5, 8)):
            subdir = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))
            path += f"/{subdir}"
        url = f"http://{domain}{tld}{path}"
        features['hasExcessiveSubDirs'] = True
        features['pathLength'] = len(path)
        features['hasLongURL'] = True
    
    elif technique == 'excessive_query_params':
        # Use many query parameters
        tld = random.choice(TLD_LEGITIMATE)
        params = []
        for _ in range(random.randint(6, 10)):
            param_name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
            param_value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5, 15)))
            params.append(f"{param_name}={param_value}")
        url = f"http://{domain}{tld}{random.choice(COMMON_PATHS)}?{'&'.join(params)}"
        features['numQueryParams'] = len(params)
        features['hasLongURL'] = True
    
    elif technique == 'keyword_stuffing':
        # Add keywords like 'login', 'secure', 'verify' to confuse users
        tld = random.choice(TLD_LEGITIMATE)
        keywords = ['secure', 'login', 'account', 'verify', 'confirm', 'password']
        domain_with_keywords = domain + '-' + '-'.join(random.sample(keywords, k=random.randint(1, 3)))
        url = f"http://{domain_with_keywords}{tld}{random.choice(COMMON_PATHS)}"
        features['domainLength'] = len(domain_with_keywords + tld)
        features['hasLongURL'] = len(url) > 100
    
    elif technique == 'suspicious_tld':
        # Use a suspicious TLD
        tld = random.choice(TLD_SUSPICIOUS)
        url = f"http://{domain}{tld}{random.choice(COMMON_PATHS)}"
        features['hasSuspiciousTLD'] = True
    
    # Sometimes add @ symbol
    if random.random() < 0.2 and '@' not in url:
        parts = url.split('://')
        if len(parts) > 1:
            username = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 8)))
            password = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5, 8)))
            url = f"{parts[0]}://{username}:{password}@{parts[1]}"
            features['hasAtSymbol'] = True
    
    # Sometimes add double slash in path
    if random.random() < 0.15 and technique != 'ip_address' and '//' not in urlparse(url).path:
        url = url.replace('com/', 'com//').replace('org/', 'org//').replace('net/', 'net//')
        features['hasDoubleSlash'] = True
    
    # Update other features
    parsed_url = urlparse(url)
    features['domainLength'] = len(parsed_url.netloc)
    features['pathLength'] = len(parsed_url.path)
    features['hasLongURL'] = len(url) > 100
    features['hasManyDots'] = url.count('.') > 3
    
    # Determine risk level
    if technique in ['ip_address', 'homograph_attack', 'subdomain_confusion']:
        risk_level = 'high'
    elif technique in ['domain_typo', 'suspicious_tld', 'url_shortener']:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'url': url,
        'is_phishing': True,
        'category': f'phishing_{technique}',
        'risk_level': risk_level,
        'features': features
    }

def generate_dataset(num_urls=500, legitimate_ratio=0.6):
    """Generate a dataset with both legitimate and phishing URLs"""
    dataset = []
    
    num_legitimate = int(num_urls * legitimate_ratio)
    num_phishing = num_urls - num_legitimate
    
    print(f"Generating {num_legitimate} legitimate URLs...")
    for _ in range(num_legitimate):
        dataset.append(generate_legitimate_url())
    
    print(f"Generating {num_phishing} phishing URLs...")
    for _ in range(num_phishing):
        dataset.append(generate_phishing_url())
    
    # Shuffle dataset
    random.shuffle(dataset)
    
    return dataset

def save_dataset_to_csv(dataset, output_file):
    """Save the dataset to a CSV file"""
    # Create the directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        # Get all possible feature keys
        all_features = set()
        for item in dataset:
            all_features.update(item['features'].keys())
        
        feature_fields = sorted(list(all_features))
        fieldnames = ['url', 'is_phishing', 'category', 'risk_level', 'features']
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for item in dataset:
            # Convert features dict to string
            row = {
                'url': item['url'],
                'is_phishing': '1' if item['is_phishing'] else '0',
                'category': item['category'],
                'risk_level': item['risk_level'],
                'features': str(item['features'])
            }
            writer.writerow(row)
    
    print(f"Dataset saved to {output_file}")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Generate a dataset of legitimate and phishing URLs')
    parser.add_argument('-n', '--num-urls', type=int, default=500,
                        help='Number of URLs to generate (default: 500)')
    parser.add_argument('-r', '--ratio', type=float, default=0.6,
                        help='Ratio of legitimate to phishing URLs (default: 0.6)')
    parser.add_argument('-s', '--seed', type=int, default=None,
                        help='Random seed for reproducibility')
    parser.add_argument('-o', '--output', type=str, default='data/phishing_dataset.csv',
                        help='Output file path (default: data/phishing_dataset.csv)')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_args()
    
    # Set random seed if provided
    if args.seed is not None:
        random.seed(args.seed)
        print(f"Using random seed: {args.seed}")
    
    # Generate dataset
    dataset = generate_dataset(num_urls=args.num_urls, legitimate_ratio=args.ratio)
    
    # Save dataset to CSV
    save_dataset_to_csv(dataset, args.output)

if __name__ == '__main__':
    main()
