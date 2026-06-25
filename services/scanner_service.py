import os
import requests
import hashlib
import base64
import time
from dotenv import load_dotenv

load_dotenv()

class ScannerService:
    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuse_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.urlscan_api_key = os.getenv('URLSCAN_API_KEY', '')
        self.gsb_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        self.ismalicious_api_key = os.getenv('ISMALICIOUS_API_KEY', '')
        self.ismalicious_api_url = os.getenv('ISMALICIOUS_API_URL', 'https://api.ismalicious.com/v1/check')

    def get_file_hash(self, file_content):
        return hashlib.sha256(file_content).hexdigest()

    # --- VirusTotal v3 API ---
    def _vt_v3_get(self, endpoint):
        if not self.vt_api_key:
            print('[VT] No API key configured')
            return None
        headers = {"x-apikey": self.vt_api_key}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers=headers, timeout=15)
            print(f'[VT] GET {endpoint} -> Status {response.status_code}')
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Status 404", "not_found": True}
            elif response.status_code == 429:
                return {"error": "Status 429 - Rate Limited", "rate_limited": True}
            return {"error": f"Status {response.status_code}", "text": response.text[:200]}
        except Exception as e:
            print(f'[VT] Exception: {e}')
            return {"error": str(e)}

    def scan_url(self, url):
        # 1. VT URL Lookup (check if already analyzed)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_data = self._vt_v3_get(f"urls/{url_id}")
        
        # 2. If not found in VT, SUBMIT it for scanning
        # Check if we got a 404/not_found response from _vt_v3_get
        is_not_found = vt_data and (vt_data.get('not_found') or vt_data.get('error') == 'Status 404')
        
        if is_not_found:
            print(f'[VT] URL {url} not found. Submitting for analysis...')
            submit_res = self._vt_v3_submit_url(url)
            # Indicate that it's newly submitted
            vt_data['newly_submitted'] = True
            vt_data['submission_id'] = submit_res.get('data', {}).get('id') if submit_res else None
        
        # 3. Google Safe Browsing
        gsb_result = self._gsb_lookup(url)
        
        # 4. URLScan
        urlscan_data = self._urlscan_scan(url)
        ismalicious_data = self._ismalicious_scan(url, 'url')
        
        return {
            'vt': self._parse_vt_stats(vt_data),
            'gsb': gsb_result,
            'urlscan': urlscan_data,
            'ismalicious': ismalicious_data,
            'raw_vt': vt_data
        }

    def scan_ip(self, ip):
        vt_data = self._vt_v3_get(f"ip_addresses/{ip}")
        abuse_data = self._abuseipdb_scan(ip)
        ismalicious_data = self._ismalicious_scan(ip, 'ip')
        
        return {
            'vt': self._parse_vt_stats(vt_data),
            'abuseipdb': abuse_data,
            'ismalicious': ismalicious_data,
            'raw_vt': vt_data
        }

    def scan_hash(self, file_hash):
        vt_data = self._vt_v3_get(f"files/{file_hash}")
        ismalicious_data = self._ismalicious_scan(file_hash, 'hash')
        return {
            'vt': self._parse_vt_stats(vt_data),
            'ismalicious': ismalicious_data,
            'raw_vt': vt_data
        }

    def scan_file(self, file_content, filename):
        file_hash = self.get_file_hash(file_content)
        # First check VT by hash
        vt_data = self.scan_hash(file_hash)
        
        # If hash not found, we SHOULD upload, but for Free API, 
        # hash check is usually safer/faster.
        # Implementation of upload if needed:
        if vt_data.get('vt', {}).get('status') == 'not_found':
            self._vt_v3_submit_file(file_content, filename)
            
        return {
            'hash': file_hash,
            'vt_result': vt_data['vt'],
            'ismalicious_result': vt_data.get('ismalicious', self._ismalicious_status('unknown')),
            'raw_vt': vt_data['raw_vt']
        }

    def _ismalicious_status(self, status, error=None):
        result = {
            'status': status,
            'is_malicious': None,
            'verdict': 'unknown',
            'confidence': None
        }
        if error:
            result['error'] = error
        return result

    def _to_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ('true', 'yes', '1', 'malicious', 'threat', 'unsafe', 'phishing', 'bad'):
                return True
            if normalized in ('false', 'no', '0', 'safe', 'clean', 'benign', 'good'):
                return False
        return None

    def _normalize_ismalicious(self, data):
        if not isinstance(data, dict):
            return self._ismalicious_status('error', 'Invalid response format from IsMalicious')

        is_malicious = None
        for key in ('is_malicious', 'malicious', 'isMalicious', 'threat', 'is_threat', 'unsafe'):
            if key in data:
                is_malicious = self._to_bool(data.get(key))
                if is_malicious is not None:
                    break

        verdict_raw = data.get('verdict') or data.get('result') or data.get('status')
        if is_malicious is None and isinstance(verdict_raw, str):
            is_malicious = self._to_bool(verdict_raw)

        confidence = data.get('confidence')
        try:
            confidence = float(confidence) if confidence is not None else None
        except (ValueError, TypeError):
            confidence = None

        normalized = {
            'status': 'success',
            'is_malicious': is_malicious,
            'verdict': 'malicious' if is_malicious is True else 'safe' if is_malicious is False else 'unknown',
            'confidence': confidence
        }
        if verdict_raw is not None:
            normalized['raw_verdict'] = str(verdict_raw)
        if data.get('message'):
            normalized['message'] = str(data.get('message'))
        return normalized

    def _ismalicious_scan(self, target, target_type):
        if not self.ismalicious_api_key:
            return self._ismalicious_status('unconfigured', 'No API key')

        payload = {'target': target, 'type': target_type}
        header_variants = (
            {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'x-api-key': self.ismalicious_api_key
            },
            {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.ismalicious_api_key}'
            }
        )

        for headers in header_variants:
            try:
                response = requests.post(self.ismalicious_api_url, headers=headers, json=payload, timeout=15)
            except Exception as e:
                return self._ismalicious_status('error', str(e))

            if response.status_code in (401, 403):
                continue
            if response.status_code == 429:
                return self._ismalicious_status('rate_limited', 'Status 429')
            if response.status_code == 404:
                return self._ismalicious_status('not_found', 'Status 404')
            if response.status_code != 200:
                return self._ismalicious_status('error', f'Status {response.status_code}')

            try:
                data = response.json()
            except ValueError:
                return self._ismalicious_status('error', 'IsMalicious returned non-JSON response')
            return self._normalize_ismalicious(data)

        return self._ismalicious_status('error', 'Authentication failed for IsMalicious API')

    def _parse_vt_stats(self, data):
        if not data:
            return {'status': 'unconfigured', 'malicious': 0, 'suspicious': 0, 'total': 0, 'risk_score': 0}
        if 'error' in data:
            err = data.get('error', '')
            if 'Status 404' in err or data.get('not_found'):
                return {'status': 'not_found', 'malicious': 0, 'suspicious': 0, 'total': 0, 'risk_score': 0}
            if 'Status 429' in err or data.get('rate_limited'):
                print('[VT] Rate limit hit')
                return {'status': 'rate_limited', 'malicious': 0, 'suspicious': 0, 'total': 0, 'risk_score': 0}
            print(f'[VT] Parse error: {data}')
            return {'status': 'error', 'malicious': 0, 'suspicious': 0, 'total': 0, 'risk_score': 0}
            
        # Handle newly submitted but not yet analyzed
        if data.get('newly_submitted'):
            return {
                'status': 'queued',
                'malicious': 0,
                'suspicious': 0,
                'total': 0,
                'risk_score': 0,
                'message': 'URL submitted for analysis. Please check back in a few minutes.'
            }

        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        if not stats:
            print(f'[VT] Unexpected data structure: {list(data.keys())}')
            return {'status': 'error', 'malicious': 0, 'suspicious': 0, 'total': 0, 'risk_score': 0}
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        
        total = malicious + suspicious + harmless + undetected
        risk_score = (malicious + suspicious) / total if total > 0 else 0
        print(f'[VT] Parsed: malicious={malicious}/{total}, risk={risk_score:.3f}')
        return {
            'status': 'success',
            'malicious': malicious,
            'suspicious': suspicious,
            'total': total,
            'risk_score': risk_score
        }

    def _vt_v3_submit_file(self, file_content, filename):
        if not self.vt_api_key: return None
        endpoint = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": self.vt_api_key}
        files = {"file": (filename, file_content)}
        try:
            response = requests.post(endpoint, headers=headers, files=files)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def _abuseipdb_scan(self, ip):
        if not self.abuse_api_key:
            return {"status": "unconfigured", "error": "No API key"}
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': True}
        headers = {'Accept': 'application/json', 'Key': self.abuse_api_key}
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                return response.json()
            return {"error": f"Status {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _vt_v3_submit_url(self, url_to_scan):
        if not self.vt_api_key: return None
        endpoint = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": self.vt_api_key}
        data = {"url": url_to_scan}
        try:
            response = requests.post(endpoint, headers=headers, data=data)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def _gsb_lookup(self, url_to_scan):
        if not self.gsb_api_key or "your_gsb" in self.gsb_api_key:
            return {"status": "unconfigured", "malicious": False}
        
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
        body = {
            "client": {"clientId": "cyber-shield", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url_to_scan}]
            }
        }
        try:
            response = requests.post(endpoint, json=body)
            if response.status_code == 200:
                data = response.json()
                if "matches" in data:
                    return {"status": "malicious", "malicious": True, "details": data["matches"]}
                return {"status": "safe", "malicious": False}
            return {"status": "error", "malicious": False, "error": response.text}
        except Exception as e:
            return {"status": "error", "malicious": False, "error": str(e)}

    def _urlscan_scan(self, url_to_scan):
        if not self.urlscan_api_key: return None
        # Ensure URL has a scheme
        if not url_to_scan.startswith(('http://', 'https://')):
            url_to_scan = 'https://' + url_to_scan
        endpoint = 'https://urlscan.io/api/v1/scan/'
        headers = {'API-Key': self.urlscan_api_key, 'Content-Type': 'application/json'}
        data = {"url": url_to_scan, "visibility": "public"}
        try:
            response = requests.post(endpoint, headers=headers, json=data)
            if response.status_code == 200:
                return response.json()
            # 400 often means already submitted or invalid format
            resp_data = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}
            return {"error": f"Status {response.status_code}", "message": resp_data.get('message', '')}
        except Exception as e:
            return {"error": str(e)}
