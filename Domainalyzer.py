import dns.resolver
import aiohttp
import asyncio
import socket
import whois
import ipaddress
import json
import logging
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import sys

# X: @owldecoy

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def fetch_aws_ranges():
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=5, headers=headers)
        data = response.json()
        return [prefix['ip_prefix'] for prefix in data['prefixes'] if prefix['service'] == 'AMAZON']
    except Exception as e:
        logging.error(f"Failed to fetch AWS IP ranges: {e}")
        return []

AWS_RANGES = fetch_aws_ranges()

def is_aws_ip(ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr) for cidr in AWS_RANGES)


def fetch_azure_ranges():
    try:
        with open('ServiceTags_Public_20250512.json', 'r') as file:
            data = json.load(file)
        return [prefix for value in data.get('values', []) for prefix in value.get('properties', {}).get('addressPrefixes', [])]
    except Exception as e:
        logging.error(f"Failed to read Azure IP ranges from file: {e}")
        return []
    except Exception as e:
        logging.error(f"Failed to fetch Azure IP ranges: {e}")
        return []
    except Exception as e:
        logging.error(f"Failed to fetch Azure IP ranges: {e}")
        return []
    except Exception as e:
        logging.error(f"Failed to fetch Azure IP ranges: {e}")
        return []

AZURE_RANGES = fetch_azure_ranges()

def is_azure_ip(ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr) for cidr in AZURE_RANGES)

def fetch_gcp_ranges():
    try:
        response = requests.get("https://www.gstatic.com/ipranges/cloud.json", timeout=5)
        data = response.json()
        return [prefix['ipv4Prefix'] for prefix in data['prefixes'] if 'ipv4Prefix' in prefix]
    except Exception as e:
        logging.error(f"Failed to fetch GCP IP ranges: {e}")
        return []

GCP_RANGES = fetch_gcp_ranges()

def is_gcp_ip(ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr) for cidr in GCP_RANGES)


class DomainAnalyzer:
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        if not self.domain.startswith(('http://', 'https://')):
            self.domain = f'https://{self.domain}'
        self.results = {
            'email_provider': None,
            'sso_provider': None,
            'cdns': [],
            'cloud_provider': None,
            'whois': {}
        }

    async def fetch(self, session, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'}                                                                                                                                                                                                                                            
            async with session.get(url, timeout=5, headers=headers) as response:
                return await response.text(), response.headers
        except Exception as e:
            logging.error(f"Request failed for {url}: {e}")
            return None, None

    def analyze_email_provider(self):
        try:
            mx_records = dns.resolver.resolve(self.domain.split('://')[1], 'MX')
            mx_domains = [str(record.exchange).lower() for record in mx_records]
            email_providers = {
                'google': ['google.com', 'googlemail.com'],
                'microsoft': ['outlook.com', 'protection.outlook.com'],
                'yahoo': ['yahoodns.net'],
                'zoho': ['zoho.com', 'zohomail.com'],
                'protonmail': ['protonmail.com'],
                'aol': ['aol.com', 'aim.com'],
                'apple': ['icloud.com', 'me.com', 'mac.com'],
                'mail.com': ['mail.com'],
                'gmx': ['gmx.com', 'gmx.us', 'gmx.de'],
                'yandex': ['yandex.com', 'yandex.ru'],
                'mail.ru': ['mail.ru'],
                'tutanota': ['tutanota.com'],
                'fastmail': ['fastmail.com'],
                'hushmail': ['hushmail.com'],
                'runbox': ['runbox.com'],
                'rackspace': ['emailsrvr.com', 'rackspace.com'],
                'hey': ['hey.com'],
                'bluehost': ['bluehost.com'],
                'ionos': ['ionos.com', '1and1.com'],
                '163.com': ['163.com'],
                'qq mail': ['qq.com'],
                'tencent': ['tencent.com'],
                'seznam': ['seznam.cz']
            }

            for provider, domains in email_providers.items():
                if any(domain in mx.lower() for mx in mx_domains for domain in domains):
                    self.results['email_provider'] = provider
                    break
            if not self.results['email_provider'] and mx_domains:
                self.results['email_provider'] = 'custom/other'
        except Exception as e:
            logging.warning(f"Error analyzing MX records: {e}")

    async def analyze_sso(self, session):
        text, headers = await self.fetch(session, self.domain)
        if not text:
            return
        sso_indicators = {
            'okta': ['x-okta', 'okta.com'],
            'azure ad': ['login.microsoftonline.com'],
            'ping identity': ['pingidentity.com'],
            'onelogin': ['onelogin.com'],
            'auth0': ['auth0.com'],
            'google identity': ['accounts.google.com', 'accounts.youtube.com'],
            'aws cognito': ['cognito-idp.amazonaws.com', 'amazoncognito.com'],
            'salesforce identity': ['salesforce.com', 'force.com', 'my.salesforce.com'],
            'duo security': ['duosecurity.com', 'api-*.duosecurity.com'],
            'secureauth': ['secureauth.com'],
            'centrify': ['centrify.com', 'cloud.centrify.com'],
            'jumpcloud': ['jumpcloud.com'],
            'ibm cloud identity': ['identity.ibm.com', 'cloud.ibm.com'],
            'keycloak': ['keycloak.org', 'auth.keycloak.com'],
            'oracle identity cloud': ['identity.oraclecloud.com'],
            'netiq': ['netiq.com'],
            'cyberark': ['cyberark.com'],
            'forgerock': ['forgerock.com'],
            'gluu': ['gluu.org'],
            'miniorange': ['miniorange.com'],
            'firebase authentication': ['firebaseapp.com', 'firebase.google.com'],
            'rippling': ['rippling.com'],
            'identityserver': ['identityserver.io'],
            'apple sign-in': ['appleid.apple.com']
        }

        for provider, indicators in sso_indicators.items():
            if any(indicator in str(headers).lower() or indicator in text.lower() for indicator in indicators):
                self.results['sso_provider'] = provider
                break

    async def analyze_cdn(self, session):
        text, headers = await self.fetch(session, self.domain)
        if not text:
            return
        cdn_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai', 'akamaiedge'],
            'fastly': ['fastly'],
            'cloudfront': ['cloudfront'],
            'sucuri': ['sucuri'],
            'azure cdn': ['azureedge.net', 'microsoft.com'],
            'google cloud cdn': ['googleusercontent.com', 'googleapis.com'],
            'stackpath': ['stackpathdns.com', 'stackpath.com'],
            'keycdn': ['keycdn.com', 'kxcdn.com'],
            'bunnycdn': ['b-cdn.net', 'bunny.net'],
            'cachefly': ['cachefly.net'],
            'cdnetworks': ['cdnetworks.com'],
            'alibaba cloud cdn': ['alicdn.com', 'taobaocdn.com'],
            'verizon edgecast': ['edgecastcdn.net', 'edgecast.com'],
            'cdn77': ['cdn77.com'],
            'limelight networks': ['llnwd.net', 'limelight.com'],
            'belugacdn': ['belugacdn.com'],
            'chinacache': ['chinacache.com'],
            'maxcdn': ['maxcdn.com'],
            'quantil': ['quantil.com'],
            'level3': ['lvlt.net'],
            'netdna': ['netdna-cdn.com'],
            'jetpack': ['wp.com', 'jetpack.com']
        }

        for cdn, indicators in cdn_indicators.items():
            if any(indicator in str(headers).lower() for indicator in indicators):
                self.results['cdns'].append(cdn)
        self.results['cdns'] = list(set(self.results['cdns']))

    def analyze_cloud_provider(self):
        try:
            hostname = urlparse(self.domain).hostname
            ip = socket.gethostbyname(hostname)

            if is_aws_ip(ip):
                self.results['cloud_provider'] = 'AWS'
            elif is_azure_ip(ip):
                self.results['cloud_provider'] = 'Azure'
            elif is_gcp_ip(ip):
                self.results['cloud_provider'] = 'Google Cloud'
        except Exception as e:
            logging.error(f"Error analyzing cloud provider: {e}")


    def analyze_whois(self):
        try:
            domain_name = urlparse(self.domain).hostname
            w = whois.whois(domain_name)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date)
            }
        except Exception as e:
            logging.error(f"WHOIS lookup failed: {e}")
    
    async def analyze(self):
        self.analyze_email_provider()
        self.analyze_cloud_provider()
        self.analyze_whois()
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(
                self.analyze_sso(session),
                self.analyze_cdn(session)
            )
        return json.dumps(self.results, indent=4)

async def analyze_domain(domain: str):
    analyzer = DomainAnalyzer(domain)
    results = await analyzer.analyze()
    print(f"\nAnalysis for {domain}:\n{results}")

if __name__ == "__main__":
    domain = sys.argv[1]
    asyncio.run(analyze_domain(domain))
