import requests
import argparse
import urllib3
import csv

def detect_gdpr_block(res):
    """
    Detect if the page is blocked due to GDPR
    returns True if it is blocked
    """
    if r.status_code == 451:
        return "Yes"
    elif r.status_code == 200:
        if "We are currently unavailable in your region" in r.text:
            return "Yes"
        if "our website is currently unavailable in most European countries" in r.text:
            return "Yes"
    elif r.status_code == 403:
        if "You don't have permission to access" in r.text:
            return "Yes"
    return "No"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scans domains looking for HTTP 451 which is GDPR restrictions')
    parser.add_argument('DOMAINS', help="Files listing domains")
    parser.add_argument('--output', '-o', help="Output file", default="output.csv")
    args = parser.parse_args()

    # Important to have a clean UA bc some websites block requests UA
    headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'}

    with open(args.DOMAINS, 'r') as f:
        sites = f.read().split('\n')

    fout = open(args.output, 'a+')
    csvout = csv.writer(fout, delimiter=",", quotechar='"')
    csvout.writerow(["Domain", "Accessible", "url", "Status Code", "Redirect to another domain", "HTML Size", "GDPR blocking"])

    for site in sites:
        if site.strip() == '':
            continue
        print("Domain: {}".format(site.strip()))
        if site.startswith('http'):
            url = site
        else:
            url = "http://{}/".format(site)
        try:
            r = requests.get(url, headers=headers, timeout=15)
        except (requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects, requests.exceptions.ReadTimeout, urllib3.exceptions.LocationParseError):
            csvout.writerow([site, "No", url, "", "", "", ""])
            print("Not accessible")
        except UnicodeError:
            csvout.writerow([site, "No", url, "", "", "", ""])
            print("Bug with the URL")
        else:
            if site in r.url:
                redir = "No"
            else:
                redir = "Yes"
            gdpr = detect_gdpr_block(r)
            print("Status code: {} / redirect {} / GDPR blocked {}".format(r.status_code, redir, gdpr))
            csvout.writerow([site, "Yes", r.url, r.status_code, redir, len(r.text), gdpr])
