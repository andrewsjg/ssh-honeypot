# ssh-honeypot

A simple SSH honey pot written on Go. Designed to collect data on attempts to login to a generic SSH server open to the internet. 

The tool runs an SSH server that rejects all login attempts. There is no session created it simply presents records the user name and password for later analysis.

**Note:** In order to use the geolocation functions you will need to provide your own copy of the GeoLite2-City database. This requires an account with Maxmind. The GeoLite2 database is provided for free.

Usage:

1. Compile the binary by simply running `go build`
2. Generate a hostkey for the fake server using `ssh-keygen` and put the private key (id_rsa) in the same directory as the server binary 
3. If you have it, put the latest GeoLite2-City.mmdb file in the same directory as the server binary
4. Run the server: `./ssh-honeypot`
5. Watch for login attempts!

Features:

* Logs JSON records of each login attempt to a file
* Simple console TUI to show live activity
* Does geolocation based on the [Maxmind GeoLite2/GeoIP2](https://dev.maxmind.com/geoip/) database


