package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/morebaconstrips/pcapwalker/utils"
)

func usage() {
	fmt.Println("Usage: pcap_analyzer {path to pcap/pcapng file} {optional: name of the file to store results - defaults to pcap_analyzer.txt}")
	fmt.Println("Example: ./pcap_analyzer network_traffic.pcap")
	os.Exit(1)
}

func msg(file *os.File, text string) {
	fmt.Println(text)
	file.WriteString(text + "\n")
}

func getArray(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var array []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		array = append(array, scanner.Text())
	}
	return array, scanner.Err()
}

func checkDependency(command string) {
	_, err := exec.LookPath(command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s is required but not found. Aborting.\n", command)
		os.Exit(1)
	}
}

func checkPermissions(filename string) {
	_, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot read %s. Check permissions.\n", filename)
		os.Exit(1)
	}
}

func validateInput(args []string) (string, string) {
	if len(args) < 1 || len(args) > 2 {
		usage()
	}

	pcapFile := args[0]
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: The specified pcap file '%s' does not exist or is not a regular file.\n", pcapFile)
		os.Exit(1)
	}

	outputFile := "pcap_analyzer.txt"
	if len(args) == 2 {
		outputFile = args[1]
	}

	if _, err := os.Stat(outputFile); err == nil {
		os.Remove(outputFile)
	}

	patternsFile := "data/patterns.txt"
	if _, err := os.Stat(patternsFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: patterns file not found: %s\n", patternsFile)
		os.Exit(1)
	}

	return pcapFile, outputFile
}


func filter(output string, numFields int) string {
    lines := strings.Split(output, "\n")
    var builder strings.Builder

    for _, line := range lines {
        fields := strings.Fields(line)
        if len(fields) == numFields {
            for _, field := range fields {
                if field == "" {
                    goto nextLine
                }
            }
            builder.WriteString(line)
            builder.WriteString("\n")
        }
    nextLine:
    }

    return builder.String()
}

func unique(output string) string {
	lines := strings.Split(output, "\n")
	uniqueLines := make(map[string]bool)
	var buffer bytes.Buffer

	for _, line := range lines {
		if _, seen := uniqueLines[line]; !seen && line != "" {
			uniqueLines[line] = true
			buffer.WriteString(line)
			buffer.WriteString("\n")
		}
	}

	return buffer.String()
}

func runTshark(pcapFile, filter string, fields []string) string {
	args := []string{"-r", pcapFile, "-Y", filter, "-T", "fields"}
	for _, field := range fields {
		args = append(args, "-e", field)
	}
	cmd := exec.Command("tshark", args...)
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running tshark: %v\n", err)
		os.Exit(1)
	}
	return unique(string(output))
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	args := os.Args[1:]
	checkDependency("tshark")

	pcapFile, outputFile := validateInput(args)
	checkPermissions(pcapFile)
	checkPermissions("data/patterns.txt")

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	msg(file, "***PCAP File***")
	msg(file, pcapFile)
	msg(file, "")

	msg(file, "***HTTP Traffic***")
	fields := []string{"frame.number", "http.host", "http.request.uri"}
	output := runTshark(pcapFile, "http", fields)
	output = filter(output, len(fields))
	msg(file, output)

	msg(file, "***DNS Requests***")
	fields = []string{"dns.qry.name"}
	output = runTshark(pcapFile, "dns", fields)
	msg(file, output)

	msg(file, "***FTP Traffic***")
	fields = []string{"ftp.request.command", "ftp.request.arg"}
	output = runTshark(pcapFile, "ftp", fields)
	msg(file, output)

	msg(file, "***SSH Traffic***")
	fields = []string{"ssh"}
	output = runTshark(pcapFile, "ssh", fields)
	msg(file, output)

	msg(file, "***Telnet Traffic***")
	fields = []string{"telnet.data"}
	output = runTshark(pcapFile, "telnet", fields)
	msg(file, output)

	msg(file, "***IP Analysis***")
	geoInfos, _ := utils.PrintGeoInfoForIPs(pcapFile)
    for _, geoInfo := range geoInfos {
        fmt.Printf("IP: %s\nCountry: %s\nCity: %s\nPostal Code: %s\nLatitude: %f\nLongitude: %f\n\n",
            geoInfo.IP, geoInfo.Country, geoInfo.City, geoInfo.Postal, geoInfo.Lat, geoInfo.Lon)
    }

	msg(file, "***Search for specific keywords in packets***")
	patterns, err := getArray("data/patterns.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading patterns file: %v\n", err)
		os.Exit(1)
	}
	for _, pattern := range patterns {
		msg(file, "-------------------- "+pattern+" --------------------")
		fields = []string{"frame.number", "frame.time", "frame.len", "data.data"}
		output = runTshark(pcapFile, fmt.Sprintf("frame matches \"(?i)%s\"", pattern), fields)
		msg(file, output)
	}

	msg(file, "***Check for known malicious domains***")
	maliciousDomains, err := getArray("data/blackbook.csv")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading blackbook file: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range maliciousDomains {
		fields := strings.Split(entry, ",")
		domain := fields[0]
		malware := fields[1]
		dateAdded := fields[2]
		source := fields[3]
		content, err := os.ReadFile(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading output file: %v\n", err)
			os.Exit(1)
		}
		if strings.Contains(string(content), domain) {
			msg(file, fmt.Sprintf("- Potential malware communication detected with domain: %s (Malware: %s, Date added: %s, Source: %s)", domain, malware, dateAdded, source))
		}
	}

	msg(file, "\n***Security Scan***")
	msg(file, "-------------------- NTP version --------------------")
	ntpVersion := getNTPVersion(pcapFile)
	if ntpVersion != "" {
	    msg(file, ntpVersion)
	}

	msg(file, "\n-------------------- SSL/TLS --------------------")
	numHandshakes, negotiatedTLSVersion, negotiatedCipherSuite := getSSL(pcapFile)
	msg(file, fmt.Sprintf("Number of SSL/TLS handshakes: %d", numHandshakes))
	msg(file, "\nNegotiated TLS versions:")
	for version := range negotiatedTLSVersion {
		msg(file, version)
	}
	msg(file, "\nNegotiated Cipher Suites:")
	for cipherSuite := range negotiatedCipherSuite {
		msg(file, cipherSuite)
	}

	cipherSuiteBlacklistMap := make(map[string]bool)
	for _, cipherSuite := range utils.CIPHER_SUITE_BLACKLIST {
	    cipherSuiteBlacklistMap[cipherSuite] = true
	}
	vulnerableCipherSuites := make(map[string]bool)
	for cipherSuite := range negotiatedCipherSuite {
	    if _, ok := cipherSuiteBlacklistMap[cipherSuite]; ok {
	        vulnerableCipherSuites[cipherSuite] = true
	    }
	}
	
	vulnerableCipherSuitesSlice := make([]string, 0, len(vulnerableCipherSuites))
	for cipherSuite := range vulnerableCipherSuites {
    vulnerableCipherSuitesSlice = append(vulnerableCipherSuitesSlice, cipherSuite)
	}
	if len(vulnerableCipherSuites) > 0 {
		msg(file, fmt.Sprintf("\n%d vulnerable cipher suite detected: %s", len(vulnerableCipherSuites), strings.Join(vulnerableCipherSuitesSlice, ", ")))
	}
	
	msg(file, "")
	msg(file, "***Analysis Complete***")

	fmt.Printf("Results saved in %s\n", outputFile)
}
