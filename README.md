# PCAPWalker

![logo](https://github.com/morebaconstrips/pcapwalker/blob/main/logo.png)

PCAP Walker is a script for analyzing pcap/pcapng network traffic capture files. It extracts various types of network traffic, searches for specific keywords in packets, checks for known malicious domains, and finds known vulnerabilities (not implemented yet)

## Features

- Analyze HTTP, DNS, SMTP, FTP, SSH, and Telnet traffic.
- Search for specific keywords in packets.
- Check for potential malware communication based on known malicious domains.
- Security scan
    - Deprecated or insecure protocols
    - Vulnerable cipher suites
- Easily customizable patterns for keyword search.

## Requirements

- Go
- tshark (Wireshark command-line utility)
- A pcap/pcapng network traffic capture file to analyze
- Optional: A patterns.txt file containing specific keywords to search for in packets

### GeoIP2 Reader
- Download the geoip2-golang package, which provides an interface to the MaxMind GeoIP2 and GeoLite2 databases:
  ```bash
  go get -u github.com/oschwald/geoip2-golang
  ```
- Download the free GeoLite2 City database from MaxMind's website. You need to sign up for a free account to access the download.
- Extract the .tar.gz file:
  ```bash
  tar -xzvf GeoLite2-City.tar.gz -C ~/pcapwalker/
  ```
Make sure GeoLite2-City_*/GeoLite2-City.mmdb is in the project root directory

## Usage

```bash
Makefile build
```
```go
./pcapwalker [path to pcap/pcapng file] [optional: name of the output file]
```
