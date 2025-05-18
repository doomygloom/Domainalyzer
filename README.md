# Domainalyzer

Identifies various attributes of a given domain, including:

- **Email Provider** (via MX records)
- **SSO (Single Sign-On) Provider** (via HTTP headers and page content)
- **CDNs (Content Delivery Networks)** (via HTTP headers and CNAME records)
- **Cloud Provider** (via IP detection and headers)
- **WHOIS Information** (registrar and creation date)

## Requirements
```sh
pip install aiohttp dnspython python-whois
```

## Usage
```sh
python Domainalyzer.py example.com
```

Example output:
```json
{
    "email_provider": "google",
    "sso_provider": "okta",
    "cdns": ["cloudflare"],
    "cloud_provider": "AWS",
    "whois": {
        "registrar": "Namecheap",
        "creation_date": "2020-05-15"
    }
}
```
