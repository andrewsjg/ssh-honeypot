package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/oschwald/geoip2-golang"
)

func passwordHandler(ctx ssh.Context, password string) bool {

	// Get Location
	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// If you are using strings that may be invalid, check that ip is not nil
	ip := net.ParseIP("216.58.204.238")
	record, err := db.City(ip)
	if err != nil {
		log.Fatal(err)
	}

	lat := fmt.Sprintf("%f", record.Location.Latitude)
	long := fmt.Sprintf("%f", record.Location.Longitude)

	ipAddr := strings.Split(ctx.RemoteAddr().String(), ":")[0]

	jsonOutput := "{user: \"" + ctx.User() + "\", password: \"" + password + "\", ip_address: \"" + ipAddr + "\",city: \"" + record.City.Names["en"] + "\", region: \"" + record.Subdivisions[0].Names["en"] + "\", country: \"" + record.Country.Names["en"] + "\",latitude: \"" + lat + "\",longitude: \"" + long + "\"}"

	log.Println(jsonOutput)

	return false
}

func main() {
	sPort := "2222"
	s := &ssh.Server{
		Addr: ":" + sPort,
		//Handler:         sessionHandler,
		PasswordHandler: passwordHandler,
	}
	log.Printf("Starting ssh-honeypot on port %s\n", sPort)
	log.Fatal(s.ListenAndServe())
}
