import requests
import json
import os
from dotenv import load_dotenv
import time
import logging

load_dotenv()

class IPEnrichment:
    def enrich_alerts(self, alerts):
        """Enrich all alerts with IP intelligence"""
        enriched_alerts = []

        for alert in alerts:
            ip = alert.get("ip_address") or alert.get("ip")

            if ip:
                enrichment = self.enrich_ip(ip)
                alert["ip_enrichment"] = enrichment
            else:
                alert["ip_enrichment"] = {}

            enriched_alerts.append(alert)

        return enriched_alerts
    def __init__(self):
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.cache_file = 'ip_cache.json'
        self.cache = self.load_cache()
        self.logger = logging.getLogger(__name__)

    def load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_cache(self):
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def enrich_ip(self, ip):
        if ip in self.cache:
            cached = self.cache[ip]
            if time.time() - cached.get('timestamp', 0) < 86400:  # 24 hours
                return cached['data']

        data = {}
        if self.abuseipdb_key:
            data.update(self.query_abuseipdb(ip))
        if self.virustotal_key:
            data.update(self.query_virustotal(ip))

        self.cache[ip] = {
            'timestamp': time.time(),
            'data': data
        }
        self.save_cache()
        return data

    def query_abuseipdb(self, ip):
        try:
            url = f'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                result = response.json()['data']
                return {
                    'abuseipdb_score': result.get('abuseConfidenceScore', 0),
                    'abuseipdb_category': result.get('category', []),
                    'abuseipdb_country': result.get('countryCode', ''),
                    'abuseipdb_isp': result.get('isp', ''),
                    'abuseipdb_usage_type': result.get('usageType', '')
                }
        except Exception as e:
            self.logger.error(f"AbuseIPDB query failed for {ip}: {e}")
        return {}

    def query_virustotal(self, ip):
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {
                'accept': 'application/json',
                'x-apikey': self.virustotal_key
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()['data']['attributes']
                return {
                    'virustotal_reputation': result.get('reputation', 0),
                    'virustotal_harmless': result.get('last_analysis_stats', {}).get('harmless', 0),
                    'virustotal_malicious': result.get('last_analysis_stats', {}).get('malicious', 0),
                    'virustotal_suspicious': result.get('last_analysis_stats', {}).get('suspicious', 0),
                    'virustotal_country': result.get('country', ''),
                    'virustotal_as_owner': result.get('as_owner', '')
                }
        except Exception as e:
            self.logger.error(f"VirusTotal query failed for {ip}: {e}")
        return {}

if __name__ == "__main__":
    enricher = IPEnrichment()
    test_ip = "8.8.8.8"
    result = enricher.enrich_ip(test_ip)
    print(f"IP Enrichment for {test_ip}: {json.dumps(result, indent=2)}")