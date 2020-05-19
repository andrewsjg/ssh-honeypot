# ssh-honeypot

A simple SSH honeypot written on Go. Strictly not a honeypot as it doesnt trap or jail anything, it simply collects data on attempts to login to a generic SSH server open to the internet. 

The tool runs an SSH server that rejects all login attempts. There is no session created it just allows a login attempt and records the user name and password  and source IP for later analysis.

## Features:

* Logs JSON records of each login attempt to a file
* Simple console TUI to show live activity
* Adds Geolocation data based on the [Maxmind GeoLite2/GeoIP2](https://dev.maxmind.com/geoip/) database

**Note:** In order to use the geolocation functions you will need to provide your own copy of the GeoLite2-City database. This requires an account with Maxmind. The GeoLite2 database is provided for free.

## Usage:

1. Compile the binary by simply running `go build`
2. Generate a hostkey for the fake server using `ssh-keygen` and put the private key (id_rsa) in the same directory as the server binary 
3. If you have it, put the latest GeoLite2-City.mmdb file in the same directory as the server binary
4. Run the server: `./ssh-honeypot`\
\
**Note:** The server starts on TCP Port 2222. To expose it to the internet you will need to map port 22 on your internet router to port 2222 on the machine your honey pot is running on.

5. Watch for login attempts!




