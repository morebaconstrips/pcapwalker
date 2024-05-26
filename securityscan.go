package main

import (
	"fmt"
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