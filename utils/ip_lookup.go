package utils

import (
	"bufio"
	"errors"
	"net"
	"os/exec"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

type GeoInfo struct {
    IP      string
    Country string
    City    string
    Postal  string
    Lat     float64
    Lon     float64
}

func geoIPLookup(ip string) (*GeoInfo, error) {
    db, err := geoip2.Open("GeoLite2-City_20240531/GeoLite2-City.mmdb")
    if err != nil {
        return nil, err
    }
    defer db.Close()

    ipAddr := net.ParseIP(ip)
    if ipAddr == nil {
        return nil, errors.New("invalid IP address")
    }

    record, err := db.City(ipAddr)
    if err != nil {
        return nil, err
    }

    country, ok := record.Country.Names["en"]
    if !ok {
        return nil, errors.New("no English name for this country")
    }

    city, ok := record.City.Names["en"]
    if !ok {
        city = "N/A"
    }

    geoInfo := &GeoInfo{
        IP:      ip,
        Country: country,
        City:    city,
        Postal:  record.Postal.Code,
        Lat:     record.Location.Latitude,
        Lon:     record.Location.Longitude,
    }

    return geoInfo, nil
}

func PrintGeoInfoForIPs(pcapFile string) ([]*GeoInfo, error) {
    cmd := exec.Command("tshark", "-r", pcapFile, "-T", "fields", "-e", "ip.src", "-e", "ip.dst")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    seen := make(map[string]bool)
    scanner := bufio.NewScanner(strings.NewReader(string(output)))
    var geoInfos []*GeoInfo
    for scanner.Scan() {
        ips := strings.Fields(scanner.Text())
        for _, ip := range ips {
            if ip == "" || seen[ip] {
                continue
            }
            seen[ip] = true

            geoInfo, err := geoIPLookup(ip)
            if err != nil {
                continue
            }

            geoInfos = append(geoInfos, geoInfo)
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return geoInfos, nil
}