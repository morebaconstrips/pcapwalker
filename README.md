# PCAPWalker

PCAP Walker is a Bash script for analyzing pcap/pcapng network traffic capture files. It extracts various types of network traffic, searches for specific keywords in packets, checks for known malicious domains, and finds known vulnerabilities (not implemented yet)

## Features

- Analyze HTTP, DNS, SMTP, FTP, SSH, and Telnet traffic.
- Search for specific keywords in packets.
- Check for potential malware communication based on known malicious domains.
- Easily customizable patterns for keyword search.

## Requirements

- Bash shell
- tshark (Wireshark command-line utility)
- A pcap/pcapng network traffic capture file to analyze
- Optional: A patterns.txt file containing specific keywords to search for in packets

## Usage

```bash
./pcapwalker.sh [path to pcap/pcapng file] [optional: name of the output file]
```