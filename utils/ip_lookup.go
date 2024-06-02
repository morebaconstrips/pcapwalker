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
    IP           string
    Country      string
    City         string
    Postal       string
    Lat          float64
    Lon          float64
    Organization string
}

func geoIPLookup(ip string) (*GeoInfo, error) {
    cityDB, err := geoip2.Open("data/GeoLite2-City.mmdb")
    if err != nil {
        return nil, err
    }
    defer cityDB.Close()

    asnDB, err := geoip2.Open("data/GeoLite2-ASN.mmdb")
    if err != nil {
        return nil, err
    }
    defer asnDB.Close()

    ipAddr := net.ParseIP(ip)
    if ipAddr == nil {
        return nil, errors.New("invalid IP address")
    }

    cityRecord, err := cityDB.City(ipAddr)
    if err != nil {
        return nil, err
    }

    asnRecord, err := asnDB.ASN(ipAddr)
    if err != nil {
        return nil, err
    }

    country, ok := cityRecord.Country.Names["en"]
    if !ok {
        return nil, errors.New("no English name for this country")
    }

    city, ok := cityRecord.City.Names["en"]
    if !ok {
        city = "N/A"
    }

    geoInfo := &GeoInfo{
        IP:           ip,
        Country:      country,
        City:         city,
        Postal:       cityRecord.Postal.Code,
        Lat:          cityRecord.Location.Latitude,
        Lon:          cityRecord.Location.Longitude,
        Organization: asnRecord.AutonomousSystemOrganization,
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