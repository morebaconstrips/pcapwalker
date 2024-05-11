#!/usr/bin/env bash
set -e
set -u

function usage {
    echo "Usage:"
    echo "$0 {path to pcap/pcapng file}\
 {optional: name of the file to store results - defaults to pcap_analyzer.txt}"
    echo "Example: ./$0 network_traffic.pcap"
    exit 1
}

function msg {
    echo "$1" | tee -a "$FILE"
}

function getArray {
    array=() # Create array
    while IFS= read -r line
    do
        array+=("$line")
    done < "$1"
}

if [[ $# -gt 2 || $# -lt 1 ]]; then
    usage
fi

PCAP_FILE="$1"
if [[ $# -eq 2 ]]; then
    FILE="$2"
else
    FILE="pcap_analyzer.txt"
fi

# Remove previous file if it exists, is a file and doesn't point somewhere
if [[ -e "$FILE" && ! -h "$FILE" && -f "$FILE" ]]; then
    rm -f "$FILE"
fi

PATTERNS_FILE="patterns.txt"
if [[ ! -f "$PATTERNS_FILE" ]]; then
    echo "Error: patterns file not found: $PATTERNS_FILE"
    exit 1
fi

msg "***PCAP File***"
msg "$PCAP_FILE"
msg ""

msg "***HTTP Traffic***"
tshark -r "$PCAP_FILE" -Y "http" -T fields -e http.host -e http.request.uri | tee -a "$FILE"
msg ""

msg "***DNS Requests***"
tshark -r "$PCAP_FILE" -Y "dns" -T fields -e dns.qry.name | tee -a "$FILE"
msg ""

msg "***SMTP Traffic***"
tshark -r "$PCAP_FILE" -Y "smtp" -T fields -e smtp.mailfrom -e smtp.rcptto | tee -a "$FILE"
msg ""

msg "***FTP Traffic***"
tshark -r "$PCAP_FILE" -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg | tee -a "$FILE"
msg ""

msg "***SSH Traffic***"
tshark -r "$PCAP_FILE" -Y "ssh" -T fields -e ssh | tee -a "$FILE"
msg ""

msg "***Telnet Traffic***"
tshark -r "$PCAP_FILE" -Y "telnet" -T fields -e telnet.data | tee -a "$FILE"
msg ""

msg "***Search for specific keywords in packets***"
getArray "patterns.txt"
patterns=("${array[@]}")
for pattern in "${patterns[@]}"
do
    msg "-------------------- $pattern --------------------"
    tshark -r "$PCAP_FILE" -Y "frame matches \"(?i)$pattern\"" -T fields -e frame.number -e frame.time -e frame.len -e data.data | tee -a "$FILE"
    msg ""
done

msg "***Check for known malicious domains***"
# Check for known malicious domains
while IFS=, read -r domain malware date_added source; do
    if grep -q "$domain" "$FILE"; then
        msg "- Potential malware communication detected with domain: $domain (Malware: $malware, Date added: $date_added, Source: $source)"
    fi
done < blackbook.csv

msg "***Identified Vulnerabilities***"
#TODO: Implement

msg ""
msg "***Analysis Complete***"

echo "Results saved in $FILE"