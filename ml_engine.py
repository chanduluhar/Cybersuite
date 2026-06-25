import re
import math
from urllib.parse import urlparse
import joblib
import os
import pandas as pd

class URLFeatureExtractor:
    @staticmethod
    def get_features(url):
        features = {}
        
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ""
        path = parsed_url.path
        
        # 1. URL Length
        features['url_length'] = len(url)
        
        # 2. Hostname Length
        features['hostname_length'] = len(hostname)
        
        # 3. Path Length
        features['path_length'] = len(path)
        
        # 4. Count of special characters
        features['count_dots'] = url.count('.')
        features['count_hyphens'] = url.count('-')
        features['count_at'] = url.count('@')
        features['count_question'] = url.count('?')
        features['count_amp'] = url.count('&')
        features['count_digits'] = sum(c.isdigit() for c in url)
        
        # 5. Presence of IP Address as Hostname
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        features['is_ip'] = 1 if re.match(ip_pattern, hostname) else 0
        
        # 6. Use of shortening services
        shortening_services = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net'
        features['is_shortened'] = 1 if re.search(shortening_services, hostname) else 0
        
        # 7. Entropy of URL (measure of randomness)
        features['entropy'] = URLFeatureExtractor.calculate_entropy(url)
        
        return features

    @staticmethod
    def calculate_entropy(s):
        if not s:
            return 0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

class PhishingModel:
    def __init__(self, model_dir='models'):
        self.model_path = os.path.join(model_dir, 'phishing_model.pkl')
        self.scaler_path = os.path.join(model_dir, 'scaler.pkl')
        self.feature_names_path = os.path.join(model_dir, 'feature_names.pkl')
        
        self.model = None
        self.scaler = None
        self.feature_names = None
        
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.feature_names = joblib.load(self.feature_names_path)
            except Exception as e:
                print(f"Error loading model: {e}")
        else:
            print(f"Warning: Model files not found in {model_dir}. Use train_model.py to create them.")

    def predict(self, url):
        features = URLFeatureExtractor.get_features(url)
        
        if self.model and self.scaler and self.feature_names:
            # Create feature vector in correct order
            X = pd.DataFrame([features])[self.feature_names]
            X_scaled = self.scaler.transform(X)
            prediction_proba = self.model.predict_proba(X_scaled)[0][1]
            return float(prediction_proba)

        # Fallback to heuristic if model is missing
        score = 0
        if features['is_ip']: score += 0.4
        if features['is_shortened']: score += 0.3
        if features['count_dots'] > 3: score += 0.2
        if features['url_length'] > 100: score += 0.1
        return min(score, 1.0)
