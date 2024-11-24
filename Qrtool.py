import os
import pyfiglet
import re 
from PIL import Image
from pyzbar.pyzbar import decode
from termcolor import colored
import qrcode
import requests

# Banner
ascii_art = pyfiglet.figlet_format("QRgun")
print(colored(ascii_art, 'blue'))

# Helper Functions
def clean_path(path):
    path = path.strip()
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    return os.path.normpath(path)

def validate_file_path(file_path):
    file_path = clean_path(file_path)
    if not os.path.exists(file_path):
        raise FileNotFoundError("There is no file.")
    return file_path

def is_suspicious_link(link):
    sus_keywords = ["login", "reset", "promo", "gift", "secure", "malware", "phishing", "suspicious", "update", "verify"]
    
    for keyword in sus_keywords:
        if keyword in link.lower():
            print(f"[!] Suspicious keyword found: {keyword}")
            return True

    if len(link) > 100:
        print("[!] Suspicious: The link is unusually long.")
        return True

    if re.search(r'@|//.*//', link):
        print("[!] Suspicious: Malformed URL structure detected.")
        return True

    print("[*] The URL appears safe.")
    return False

def generate_qr():
    url = input("Enter the URL to encode in the QR >>>> ")
    qr = qrcode.make(url)
    script_dir = os.path.dirname(os.path.abspath(__file__))  
    output_path = os.path.join(script_dir, "generated_qr.png")
    qr.save(output_path)
    print(colored(f"[*] QR Code saved as '{output_path}'", "green"))

def analyze_qr():
    try:
        img_path = input("Enter the QR image path >>>> ")
        img_path = validate_file_path(img_path)

        if not img_path.lower().endswith(('png', 'jpg', 'jpeg')):
            raise ValueError("Invalid file format. Only PNG, JPG, and JPEG are supported.")

        img = Image.open(img_path)
        qr_data = decode(img)

        if qr_data:
            qr_content = qr_data[0].data.decode('utf-8')
            print(f"QR Info: {qr_content}")

            if qr_content.startswith(("http://", "https://")):
                if is_suspicious_link(qr_content):
                    print(colored("Warning!!! This link might be suspicious.", "red"))
                else:
                    print(colored("The link appears safe.", "green"))
            else:
                print(colored("The QR contains text data.", "yellow"))
        else:
            print(colored("No QR data found in the image!", "red"))

    except FileNotFoundError:
        print(colored("Error: The file was not found, please check the path and try again.", "red"))
    except ValueError as ve:
        print(colored(f"Error: {ve}", "red"))
    except Exception as e:
        print(colored(f"An unexpected error occurred: {e}", "red"))

def parse_virustotal_response(response):
    try:
        data = response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("stats", {})
        meta = response.get("meta", {}).get("url_info", {})

        status = attributes.get("status", "unknown")
        print(f"[*] Scan Status: {status.capitalize()}")

        print("[*] Scan Statistics:")
        print(f"    Malicious: {stats.get('malicious', 0)}")
        print(f"    Suspicious: {stats.get('suspicious', 0)}")
        print(f"    Undetected: {stats.get('undetected', 0)}")
        print(f"    Harmless: {stats.get('harmless', 0)}")
        print(f"    Timeout: {stats.get('timeout', 0)}")


    except Exception as e:
        print(f"[!] Error parsing response: {e}")

def scan_url():
    api_key = "change it with ur api key"
    url = input("Enter the URL to scan >>>> ")

    try:
        headers = {"x-apikey": api_key}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})

        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]
            print(colored(f"[*] URL submitted successfully. Scan ID: {scan_id}", "green"))

            print("[*] Fetching scan results...")
            scan_result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            if scan_result.status_code == 200:
                parse_virustotal_response(scan_result.json())
            else:
                print(colored("Error while fetching the scan results.", "red"))
        else:
            print(colored("Error while submitting the URL for scanning.", "red"))

    except Exception as e:
        print(colored(f"An unexpected error occurred: {e}", "red"))

def main():
    while True:
        print("\n[1] Generate QR Code")
        print("[2] Analyze QR Code")
        print("[3] Scan URL for Threats")
        print("[0] Exit")
        choice = input("Select an option >>>> ")

        if choice == "1":
            generate_qr()
        elif choice == "2":
            analyze_qr()
        elif choice == "3":
            scan_url()
        elif choice == "0":
            print(colored("Exiting... Goodbye!", "blue"))
            break
        else:
            print(colored("Invalid option. Please try again.", "red"))

if __name__ == "__main__":
    main()
