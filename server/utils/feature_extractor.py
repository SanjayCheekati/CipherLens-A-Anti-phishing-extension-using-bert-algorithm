"""
Feature Extractor - Extracts features from URLs and HTML content for phishing detection
Enhanced version with more comprehensive detection patterns
"""
import re
import logging
import socket
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FeatureExtractor:
    def __init__(self):
        # Expanded list of suspicious TLDs
        self.suspicious_tlds = [
            ".xyz", ".top", ".gq", ".ml", ".ga", ".cf", ".tk", ".info", 
            ".work", ".pro", ".men", ".loan", ".click", ".date", ".racing",
            ".online", ".stream", ".win", ".review", ".vip", ".party", ".shop",
            ".gdn", ".bid", ".accountant", ".website", ".space"
        ]
        
        # Common brands targeted by phishing
        self.popular_brands = [
            "paypal", "apple", "microsoft", "amazon", "netflix", "facebook", 
            "google", "instagram", "twitter", "gmail", "wellsfargo", "chase", 
            "bankofamerica", "bank", "coinbase", "blockchain", "linkedin",
            "dropbox", "yahoo", "instagram", "spotify", "steam", "github",
            "outlook", "hotmail", "netflix", "office365", "protonmail"
        ]
        
        # Expanded list of sensitive keywords
        self.sensitive_keywords = [
            "password", "credit card", "login", "signin", "bank", "account",
            "social security", "ssn", "credentials", "verification", "authorize",
            "secure", "update your account", "verify", "confirm", "validate",
            "unusual activity", "access", "limited", "expired", "billing",
            "payment", "authenticate", "unusual sign-in", "security", "alert",
            "suspicious", "log-in", "customer", "click here", "important",
            "urgent", "attention", "suspended", "locked", "verify now",
            "enable", "disable", "deactivate", "reactivate", "recover", "reset"
        ]

        # Common phishing TLD misspellings of legitimate domains
        self.tld_substitutions = {
            ".com": [".cm", ".co", ".om", ".commm", ".comm", ".com-secure", ".con"],
            ".org": [".ogr", ".or", ".arg", ".orgg"],
            ".net": [".ner", ".ne", ".nt", ".nett"],
            ".edu": [".ed", ".eu", ".eddu"],
            ".gov": [".gv", ".goo", ".gou", ".goc"]
        }
    
    def extract_from_url(self, url: str) -> Dict[str, float]:
        """
        Extract features from a URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # Check for IP address
            features["hasIPAddress"] = 1.0 if self._has_ip_address(domain) else 0.0
            
            # Check URL length
            if len(url) > 100:
                features["urlLength"] = 1.0
            elif len(url) > 75:
                features["urlLength"] = 0.8
            elif len(url) > 50:
                features["urlLength"] = 0.5
            else:
                features["urlLength"] = 0.0
            
            # Check for @ symbol
            features["hasAtSymbol"] = 1.0 if "@" in url else 0.0
            
            # Check for multiple subdomains
            subdomain_count = domain.count(".")
            if subdomain_count > 3:
                features["hasManySubdomains"] = 1.0
            elif subdomain_count > 2:
                features["hasManySubdomains"] = 0.7
            else:
                features["hasManySubdomains"] = 0.0
            
            # Check for suspicious TLD
            features["hasSuspiciousTLD"] = 1.0 if self._has_suspicious_tld(domain) else 0.0
            
            # Check for brand impersonation
            brand_score = self._check_brand_impersonation(domain, path)
            features["hasBrandImpersonation"] = brand_score
            
            # Check for hyphens
            hyphen_count = domain.count("-")
            if hyphen_count > 2:
                features["hasHyphens"] = 1.0
            elif hyphen_count > 1:
                features["hasHyphens"] = 0.7
            elif hyphen_count == 1:
                features["hasHyphens"] = 0.3
            else:
                features["hasHyphens"] = 0.0
            
            # Check for redirect patterns
            redirect_score = self._check_redirect_patterns(url)
            features["hasRedirectPattern"] = redirect_score
            
            # Check for deceptive hostname
            deceptive_score = self._check_deceptive_hostname(domain)
            features["hasDeceptiveHostname"] = deceptive_score
            
            # Check for HTTPS
            features["isNotHttps"] = 0.0 if parsed_url.scheme == "https" else 1.0
            
            # Certificate issues would require a separate check in a real implementation
            features["hasCertificateIssues"] = 0.0
            
            # Domain age simulation (in reality would query WHOIS database)
            # For demonstration, using random value based on domain characteristics
            import hashlib
            domain_hash = int(hashlib.md5(domain.encode()).hexdigest(), 16) % 100
            if any(brand in domain for brand in self.popular_brands) and domain_hash < 80:
                features["domainAge"] = 0.8 if domain_hash < 60 else 0.5  # Likely new domain impersonating a brand
            else:
                features["domainAge"] = 0.0
            
            # Alexa rank simulation
            features["lowAlexaRank"] = features["domainAge"]  # Simplification for demo
            
            logger.info(f"Extracted URL features: {features}")
            return features
            
        except Exception as e:
            logger.error(f"Error extracting URL features: {str(e)}")
            # Return empty features in case of error
            return {}
    
    def extract_from_content(self, content: str) -> Dict[str, float]:
        """
        Extract features from HTML content
        
        Args:
            content: HTML content to analyze
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        try:
            # Parse HTML
            soup = BeautifulSoup(content, "html.parser")
            
            # Check for password fields
            password_fields = soup.find_all("input", {"type": "password"})
            features["hasPasswordField"] = 1.0 if password_fields else 0.0
            
            # Check for login forms
            login_forms = soup.find_all("form")
            has_login_form = False
            for form in login_forms:
                form_text = form.get_text().lower()
                form_action = form.get("action", "")
                
                # Check if form has login-related keywords or input fields
                if any(kw in form_text for kw in ["login", "sign in", "signin", "log in"]):
                    has_login_form = True
                    break
                
                # Check for password fields within the form
                if form.find("input", {"type": "password"}):
                    has_login_form = True
                    break
            
            features["hasLoginForm"] = 1.0 if has_login_form else 0.0
            
            # Check for sensitive keywords with weighting based on context
            text = soup.get_text().lower()
            keyword_count = sum(1 for keyword in self.sensitive_keywords if keyword.lower() in text)
            
            if keyword_count > 5:
                features["hasSensitiveKeywords"] = 1.0
            elif keyword_count > 3:
                features["hasSensitiveKeywords"] = 0.7
            elif keyword_count > 1:
                features["hasSensitiveKeywords"] = 0.4
            else:
                features["hasSensitiveKeywords"] = 0.0
            
            # Check for form action mismatch
            forms = soup.find_all("form")
            has_mismatched_form = False
            
            for form in forms:
                action = form.get("action", "")
                if action and action.startswith("http"):
                    # Compare with the current domain in a real implementation
                    has_mismatched_form = True
                    break
            
            features["mismatchedFormAction"] = 1.0 if has_mismatched_form else 0.0
            
            # Check for external scripts
            scripts = soup.find_all("script")
            external_script_count = 0
            
            for script in scripts:
                src = script.get("src", "")
                if src and src.startswith("http"):
                    external_script_count += 1
            
            if external_script_count > 5:
                features["hasExternalScripts"] = 0.9
            elif external_script_count > 2:
                features["hasExternalScripts"] = 0.6
            elif external_script_count > 0:
                features["hasExternalScripts"] = 0.3
            else:
                features["hasExternalScripts"] = 0.0
            
            # Check for obfuscated code
            script_content = " ".join([script.string for script in scripts if script.string])
            obfuscation_score = self._check_for_obfuscation(script_content)
            features["hasObfuscatedCode"] = obfuscation_score
            
            # Check for hidden elements
            hidden_elements = soup.find_all(["input", "div", "span", "p"], style=lambda s: s and "display:none" in s.replace(" ", ""))
            hidden_elements.extend(soup.find_all("input", {"type": "hidden"}))
            
            if len(hidden_elements) > 10:
                features["hasHiddenElements"] = 0.9
            elif len(hidden_elements) > 5:
                features["hasHiddenElements"] = 0.6
            elif len(hidden_elements) > 2:
                features["hasHiddenElements"] = 0.3
            else:
                features["hasHiddenElements"] = 0.0
            
            # Check for favicon mismatch (simplified implementation)
            favicon_links = soup.find_all("link", rel=lambda r: r and "icon" in r.lower())
            favicon_urls = [link.get("href", "") for link in favicon_links]
            
            # In a real implementation, would download favicon and compare with known brands
            features["hasFaviconMismatch"] = 0.0
            if favicon_urls:
                for url in favicon_urls:
                    if not url.startswith(("http", "/")):
                        features["hasFaviconMismatch"] = 0.7
                        break
            
            logger.info(f"Extracted content features: {features}")
            return features
            
        except Exception as e:
            logger.error(f"Error extracting content features: {str(e)}")
            # Return empty features in case of error
            return {}
    
    def _has_ip_address(self, domain: str) -> bool:
        """Check if a domain is an IP address"""
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        return bool(re.match(ip_pattern, domain))
    
    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check if a domain has a suspicious TLD"""
        return any(domain.endswith(tld) for tld in self.suspicious_tlds)
    
    def _check_brand_impersonation(self, domain: str, path: str) -> float:
        """
        Check if the domain or path contains brand names but isn't the official domain
        
        Args:
            domain: Domain to check
            path: URL path to check
            
        Returns:
            Impersonation score (0-1)
        """
        # Remove TLD and www for cleaner comparison
        clean_domain = domain.lower()
        for tld in [".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".us", ".ca", ".uk"] + self.suspicious_tlds:
            clean_domain = clean_domain.replace(tld, "")
        
        clean_domain = clean_domain.replace("www.", "")
        
        # Check for brand names in domain
        domain_parts = re.split(r'[.-]', clean_domain)
        
        # Check for homograph attacks (similar-looking characters)
        homograph_mappings = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'b', '7': 't',
            'rn': 'm', 'cl': 'd', 'vv': 'w', 'goog1e': 'google', 'paypai': 'paypal'
        }
        
        # Apply homograph mappings to domain parts
        mapped_domain_parts = []
        for part in domain_parts:
            mapped_part = part
            for k, v in homograph_mappings.items():
                mapped_part = mapped_part.replace(k, v)
            mapped_domain_parts.append(mapped_part)
        
        # Check original and mapped parts
        parts_to_check = domain_parts + mapped_domain_parts
        brand_in_domain = False
        
        for brand in self.popular_brands:
            # Exact match or very close match
            if brand in parts_to_check:
                brand_in_domain = True
                break
            
            # Partial match with high similarity
            for part in parts_to_check:
                if len(part) > 3 and len(brand) > 3:
                    similarity = self._string_similarity(part, brand)
                    if similarity > 0.8:
                        brand_in_domain = True
                        break
            
            if brand_in_domain:
                break
        
        # Check for combined terms like "paypalverify" or "secure-paypal"
        if not brand_in_domain:
            for brand in self.popular_brands:
                for part in parts_to_check:
                    if len(part) > len(brand) and brand in part:
                        brand_in_domain = True
                        break
        
        # Check for brand in subdomains combined with TLDs (e.g., paypal.com.malicious.xyz)
        if not brand_in_domain and domain.count('.') >= 2:
            for brand in self.popular_brands:
                brand_domain_pattern = f"{brand}.com"
                if brand_domain_pattern in domain and domain != f"www.{brand_domain_pattern}" and domain != brand_domain_pattern:
                    brand_in_domain = True
                    break
        
        # Check path for brand mentions with sensitive terms
        path_score = 0.0
        path_parts = path.lower().split('/')
        
        for brand in self.popular_brands:
            if brand in path.lower():
                # Check if combined with security terms
                security_terms = ['secure', 'login', 'verify', 'account', 'signin', 'update', 'confirm']
                for term in security_terms:
                    if term in path_parts or f"{term}-{brand}" in path.lower() or f"{brand}-{term}" in path.lower():
                        path_score = 0.9
                        break
                
                # If brand is in path but not with security terms
                if path_score < 0.5:
                    path_score = 0.7
        
        # Higher score if brand in domain
        if brand_in_domain:
            return 0.9
        # Medium-high score if brand in path with security terms
        elif path_score > 0.5:
            return path_score
        # Low score otherwise
        else:
            return 0.0
    
    def _check_redirect_patterns(self, url: str) -> float:
        """
        Check for redirect patterns in URL
        
        Args:
            url: URL to check
            
        Returns:
            Redirect score (0-1)
        """
        # Check for redirection patterns in the URL
        redirect_patterns = [
            "url=", "redirect=", "link=", "goto=", "to=", "target=", "u=", "r=",
            "return=", "return_to=", "returnto=", "return-to=", "cgi-bin/redirect.cgi",
            "out/", "window.location=", ".php?url=", "redir/", "redirect/", "go/",
            "out?", "transfer", "linkto=", "visit=", "forward=", "navigate=", ".php?"
        ]
        
        # Check for encoded URLs embedded in the parameters
        has_encoded_url = "http%3A" in url or "https%3A" in url
        
        # Check for multiple redirects (e.g., redirect=http://...)
        has_multiple_redirects = re.search(r'(https?:|url=|redirect=).*?(https?:|url=|redirect=)', url) is not None
        
        # Check for base64 encoded parameters (potential redirect)
        has_base64 = bool(re.search(r'[a-zA-Z0-9+/]{30,}={0,2}(?:[&?]|$)', url))
        
        # Check for redirect patterns
        for pattern in redirect_patterns:
            if pattern in url.lower():
                # Higher score for multiple indicators
                if has_encoded_url or has_base64 or has_multiple_redirects:
                    return 0.9
                return 0.8
        
        # Check only for encoded URLs or base64 without redirect patterns
        if has_encoded_url:
            return 0.7
        elif has_base64:
            return 0.6
        elif has_multiple_redirects:
            return 0.7
        
        return 0.0
    
    def _check_deceptive_hostname(self, domain: str) -> float:
        """
        Check for deceptive hostnames
        
        Args:
            domain: Domain to check
            
        Returns:
            Deceptive score (0-1)
        """
        # Strip www and split by dots
        domain = domain.lower().replace("www.", "")
        parts = domain.split(".")
        
        # Check for TLD in subdomain (e.g., domain.com.malicious.org)
        has_tld_in_name = any(f".{tld[1:]}" in domain for tld in self.suspicious_tlds + [".com", ".org", ".net"])
        
        # Check for random/meaningless subdomains (entropy-based)
        subdomain_entropy = self._calculate_entropy(parts[0]) if len(parts) > 1 else 0
        has_high_entropy = subdomain_entropy > 3.5
        
        # Check for excessively long domain name
        is_long_domain = len(domain) > 30
        
        # Check for domain with misleading TLD substitutions
        has_misleading_tld = False
        domain_without_tld = '.'.join(parts[:-1]) if len(parts) > 1 else parts[0]
        tld = f".{parts[-1]}" if len(parts) > 1 else ""
        
        for real_tld, fake_tlds in self.tld_substitutions.items():
            # Check for domains like paypal.cm instead of paypal.com
            for brand in self.popular_brands:
                if domain_without_tld == brand and tld in fake_tlds:
                    has_misleading_tld = True
                    break
        
        # Calculate final score based on deceptive indicators
        score = 0.0
        if has_misleading_tld:
            score = max(score, 1.0)  # Critical indicator
        if has_tld_in_name:
            score = max(score, 0.9)  # Very strong indicator
        if has_high_entropy and is_long_domain:
            score = max(score, 0.8)  # Strong indicator
        elif has_high_entropy:
            score = max(score, 0.7)  # Moderate indicator
        elif is_long_domain:
            score = max(score, 0.5)  # Weak indicator
        
        return score
    
    def _check_for_obfuscation(self, script_content: str) -> float:
        """Check for signs of obfuscated JavaScript"""
        if not script_content:
            return 0.0
        
        obfuscation_indicators = 0
        
        obfuscation_patterns = [
            (r"eval\s*\(", 3),
            (r"document\.write\s*\(\s*unescape\s*\(", 3),
            (r"String\.fromCharCode\(", 2),
            (r"\\x[0-9a-f]{2}", 2),
            (r"\\u[0-9a-f]{4}", 2),
            (r"^[a-zA-Z0-9+/]{100,}={0,2}$", 3),  # Base64-like content
            (r"function\(\s*\w\s*,\s*\w\s*,\s*\w\s*,\s*\w\s*\)", 1),  # Potentially minified
            (r"\w=\[\];\w=\(\);", 2)  # Array manipulation obfuscation
        ]
        
        for pattern, weight in obfuscation_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                obfuscation_indicators += weight
        
        # Check entropy of content (higher entropy suggests encryption/encoding)
        entropy = self._calculate_entropy(script_content)
        if entropy > 4.5:  # High entropy
            obfuscation_indicators += 2
        
        # Normalize to 0-1 range
        return min(obfuscation_indicators / 10.0, 1.0)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text to identify encoded content"""
        import math
        
        if not text:
            return 0
        
        # Count character frequencies
        char_count = {}
        for char in text:
            char_count[char] = char_count.get(char, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0
        
        for count in char_count.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _string_similarity(self, s1: str, s2: str) -> float:
        """
        Calculate similarity between two strings
        Simple implementation - in production would use Levenshtein distance
        """
        if not s1 or not s2:
            return 0.0
        
        # Convert to lowercase
        s1, s2 = s1.lower(), s2.lower()
        
        # Simple matching coefficient
        matches = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        max_length = max(len(s1), len(s2))
        
        return matches / max_length if max_length > 0 else 0.0 