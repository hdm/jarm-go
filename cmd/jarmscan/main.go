package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/RumbleDiscovery/jarm-go"
)

func fingerprint(host string, port int) (string, error) {
	results := []string{}
	for _, probe := range jarm.GetProbes(host, port) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), time.Second*2)
		if err != nil {
			return "", err
		}

		data := jarm.BuildProbe(probe)
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, err = c.Write(data)
		if err != nil {
			results = append(results, "")
			continue
		}

		c.SetReadDeadline(time.Now().Add(time.Second * 5))
		buff := make([]byte, 1484)
		c.Read(buff)
		c.Close()

		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}

		results = append(results, ans)
	}

	return jarm.RawHashToFuzzyHash(strings.Join(results, ",")), nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: ./jarm [host]")
	}
	fp, err := fingerprint(os.Args[1], 443)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("JARM: %s\n", fp)
}
