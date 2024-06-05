"""
Subdomain Finder
Author: GHADIR BIN DHABBAH
"""

import requests
import re
from concurrent.futures import ThreadPoolExecutor

def extract_subdomains(domain):
    subdomains = set()

    # Use various sources to find subdomains
    sources = [
        f"https://crt.sh/?q=%.{domain}",
        f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
        f"https://dns.bufferover.run/dns?q=.{domain}",
        f"https://api.seon.io/api/v1/domain/{domain}/subdomains",
        f"https://api.spyse.com/v2/subdomains?domain={domain}"
    ]

    with ThreadPoolExecutor() as executor:
        results = [executor.submit(make_request, source) for source in sources]
        for future in results:
            try:
                response = future.result()
                subdomains.update(re.findall(r"[\w\-]+\.{}".format(domain), response))
            except:
                pass

    return list(subdomains)

def make_request(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def main():
    target_domain = input("Enter the target domain: ")

    subdomains = extract_subdomains(target_domain)

    with open(f"{target_domain}_report.txt", "w") as f:
        if subdomains:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        else:
            f.write(f"No subdomains found for {target_domain}.")

    print(f"Results saved to {target_domain}_report.txt")

if __name__ == "__main__":
    main()


