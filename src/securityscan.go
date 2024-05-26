package main

import (
	"fmt"
    "github.com/morebaconstrips/pcapwalker/utils"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func getNTPVersion(pcapFile string) string {
    args := []string{"-r", pcapFile, "-Y", "ntp", "-T", "fields", "-e", "ntp.flags.vn"}
    cmd := exec.Command("tshark", args...)
    output, err := cmd.Output()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error running tshark: %v\n", err)
        os.Exit(1)
    }

    ntpVersionOutput := strings.TrimSpace(string(output))
    if ntpVersionOutput == "" {
        return ""
    }

    versions := strings.Split(ntpVersionOutput, "\n")
    var minVersion int = 4 // NTP version should not exceed this number
    for _, version := range versions {
        if version != "" {
            v, err := strconv.Atoi(version)
            if err == nil && v < minVersion {
                minVersion = v
            }
        }
    }

    if minVersion != 4 {
        return "Version 4 detected - secure"
    } else {
        return fmt.Sprintf("Version %d detected - insecure", minVersion)
    }
}

func getSSL(pcapFile string) (int, map[string]bool, map[string]bool) {
    negotiatedTLSVersion := make(map[string]bool)
    negotiatedCipherSuite := make(map[string]bool)
    numHandshakes, tlsVersions, cipherSuites := getSSLHandshakeInfo(pcapFile)
    for _, tlsVersion := range tlsVersions {
        negotiatedTLSVersion[getNegotiatedTLSVersion(tlsVersion)] = true
    }
    for _, cipherSuite := range cipherSuites {
        negotiatedCipherSuite[getNegotiatedCipherSuite(cipherSuite)] = true
    }
    return numHandshakes, negotiatedTLSVersion, negotiatedCipherSuite
}

func getSSLHandshakeInfo(pcapFile string) (int, []string, []string) {
	cmd1 := exec.Command("tshark", "-r", pcapFile, "-Y", "ssl.handshake.type == 2", "-T", "fields", "-e", "frame.number")
	output1, _ := cmd1.Output()
	sslHandshakePackets := strings.Split(string(output1), "\n")
	
	// Remove duplicates
	sslHandshakePacketsSet := make(map[string]bool)
	for _, packet := range sslHandshakePackets {
		if packet != "" { // to avoid adding empty strings
			sslHandshakePacketsSet["frame.number == "+packet] = true
		}
	}
	
	// Convert the set of frames to a slice
	sslHandshakePacketsSlice := make([]string, 0, len(sslHandshakePacketsSet))
	for packet := range sslHandshakePacketsSet {
		sslHandshakePacketsSlice = append(sslHandshakePacketsSlice, packet)
	}
	
	// Convert the slice of frames to a string of conditions for the display filter
	framesFilter := strings.Join(sslHandshakePacketsSlice, " || ")
	
    cmd2 := exec.Command("tshark", "-r", pcapFile, "-Y", fmt.Sprintf("(%s) && ssl.handshake", framesFilter), "-T", "fields", "-e", "ssl.handshake.version", "-e", "ssl.handshake.ciphersuite")
    output2, _ := cmd2.Output()

	// Split the output into lines and process each line
    tlsVersions := []string{}
    cipherSuites := []string{}
    for _, line := range strings.Split(string(output2), "\n") {
        fields := strings.Fields(line)
        if len(fields) >= 2 {
            tlsVersion := fields[0]
            cipherSuite := fields[1]

            // Add tlsVersion and cipherSuite to their respective slices if they're not already present
            if !contains(tlsVersions, tlsVersion) {
                tlsVersions = append(tlsVersions, tlsVersion)
            }
            if !contains(cipherSuites, cipherSuite) {
                cipherSuites = append(cipherSuites, cipherSuite)
            }
        }
    }

    return len(sslHandshakePacketsSet), tlsVersions, cipherSuites
}

func contains(slice []string, str string) bool {
    for _, v := range slice {
        if v == str {
            return true
        }
    }
    return false
}

func getNegotiatedTLSVersion(tlsVersion string) string {
    mappedVersion, ok := utils.TLS_VERSION_MAPPING[tlsVersion]
    if ok {
        return mappedVersion
    }
    return tlsVersion
}

func getNegotiatedCipherSuite(cipherSuite string) string {
    cipherSuite = strings.TrimPrefix(cipherSuite, "0x")
    cipherSuiteInt, err := strconv.ParseInt(cipherSuite, 16, 64)
    if err != nil {
        return cipherSuite
    }
    cipherSuiteHex := fmt.Sprintf("%#x", cipherSuiteInt)
    mappedSuite, ok := utils.CIPHER_SUITE_MAPPING[cipherSuiteHex]
    if ok {
        return mappedSuite
    }
    return cipherSuite
}