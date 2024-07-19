import dns.exception
import dns.resolver
import socket
import pyfiglet
import argparse
import time
import sys
from colorama import init, Fore
from tabulate import tabulate

init()

def print_banner():
    font = pyfiglet.Figlet(font='ghost')
    banner = font.renderText("Pleer")
    print(Fore.RED + banner)
    print("* Looks for real IP that are closed by Cloudflare *")
    print(Fore.YELLOW + "\n****************************************************")
    print(Fore.GREEN + "====================================================")
    print("Author: eixploits")
    print("Github: ")
    print(Fore.GREEN + "====================================================")
    print(Fore.YELLOW + "****************************************************")

def print_scanning_effect(text, duration, delay=0.1):
    start_time = time.time()
    scanning_chars = ['|', '/', '-', '\\']
    
    while (time.time() - start_time) < duration:
        for char in scanning_chars:
            sys.stdout.write(f'\r{Fore.GREEN}{char} {text}')
            sys.stdout.flush()
            time.sleep(delay)
    sys.stdout.write('\r' + ' ' * (len(text) + 2) + '\r')
    sys.stdout.flush()

def enumerate_subdomains(domain):
    print(Fore.GREEN + "Start Scanning Enumerate Sub Domains ...")
    subdomains = ['www', 'mail', 'ftp', 'test', 'dev']
    found_ips = []

    # Set custom DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS servers

    start_time = time.time()

    for sub in subdomains:
        try:
            subdomain = f"{sub}.{domain}"
            answers = resolver.resolve(subdomain, 'A')
            for rdata in answers:
                found_ips.append((subdomain, rdata.to_text()))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers):
            continue

    elapsed_time = time.time() - start_time
    print_scanning_effect("Scanning", elapsed_time)
    return found_ips

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)
    except socket.herror:
        return None

def get_ptr_record(ip):
    try:
        reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
        answers = dns.resolver.resolve(reversed_ip, 'PTR')
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return ["No PTR record found"]
    except dns.exception.DNSException as e:
        print(f"DNS Exception: {e}")
        return ["DNS Exception"]

if __name__ == '__main__':
    print_banner()
    parser = argparse.ArgumentParser(description='Generate a banner for the given domain.')
    parser.add_argument('domain', type=str, help='The domain name to be used in the banner.')
    args = parser.parse_args()

    # Enumerate subdomains and get IP addresses
    found_ips = enumerate_subdomains(args.domain)
    headers_table = ['Subdomain', 'IP Address']
    print(Fore.YELLOW + tabulate(found_ips, headers=headers_table, tablefmt='grid'))

    # Collect IP addresses from found IPs
    ip_addresses = [ip for _, ip in found_ips]

    if not ip_addresses:
        print(Fore.RED + "IP Address Not Found")
    else:
        # Start reverse DNS scanning
        print(Fore.GREEN + "Start Reverse DNS ...")
        start_time = time.time()

        # Collect results for reverse DNS lookup and PTR records
        ptr_results = []
        for ip in ip_addresses:
            reverse_dns_result = reverse_dns(ip)
            ptr_record_result = get_ptr_record(ip)
            if reverse_dns_result:
                ptr_results.append((ip, reverse_dns_result[0], ptr_record_result))
                print(Fore.GREEN + f"{ip}: {reverse_dns_result[0]}")
            else:
                ptr_results.append((ip, "No PTR record found", ptr_record_result))
                print(Fore.RED + f"{ip}: No PTR record found")

        elapsed_time = time.time() - start_time
        print_scanning_effect("Reverse DNS Scanning", elapsed_time)

        # Determine which IPs might be the real ones based on PTR records
        real_ips = [ip for ip, _, ptr in ptr_results if ptr and ptr != "No PTR record found"]

        if real_ips:
            print(Fore.GREEN + "\nPossible Real IPs:")
            for ip in real_ips:
                print(Fore.GREEN + f"- {ip}")
        else:
            print(Fore.RED + "No possible real IPs found")
