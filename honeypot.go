package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/oschwald/geoip2-golang"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

var textUpdates chan string

type LoginData struct {
	Date      time.Time `json:"date"`
	User      string    `json:"user"`
	Password  string    `json:"password"`
	IPAddress string    `json:"ip_address"`
	City      string    `json:"city"`
	Region    string    `json:"region"`
	Country   string    `json:"country"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"Longitude"`
}

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

	// Create a log file

	lat := fmt.Sprintf("%f", record.Location.Latitude)
	long := fmt.Sprintf("%f", record.Location.Longitude)

	ipAddr := strings.Split(ctx.RemoteAddr().String(), ":")[0]

	dateStr := time.Now()

	jsonOutput := "{\"date\": \"" + dateStr.Format(time.RFC3339) + "\",\"user\": \"" + ctx.User() + "\", \"password\": \"" + password + "\", \"ip_address\": \"" + ipAddr + "\",\"city\": \"" + record.City.Names["en"] + "\", \"region\": \"" + record.Subdivisions[0].Names["en"] + "\", \"country\": \"" + record.Country.Names["en"] + "\",\"latitude\":" + lat + ",\"longitude\":" + long + "}"

	textUpdates <- jsonOutput
	log.Println(jsonOutput)

	return false
}

func main() {

	textUpdates = make(chan string)

	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()
	sPort := "2222"

	startUp := fmt.Sprintf("SSH Honeypot - Started: "+time.Now().Format(time.RFC3339)+" on port %s\n", sPort)
	waitMsg := fmt.Sprintf("[" + time.Now().Format(time.RFC3339) + "](fg:blue) - Waiting for first login attempt")
	//randomText := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.Curabitur pretium tincidunt lacus. Nulla gravida orci a odio. Nullam varius, turpis et commodo pharetra, est eros bibendum elit, nec luctus magna felis sollicitudin mauris. Integer in mauris eu nibh euismod gravida. Duis ac tellus et risus vulputate vehicula. Donec lobortis risus a elit. Etiam tempor. Ut ullamcorper, ligula eu tempor congue, eros est euismod turpis, id tincidunt sapien risus a quam. Maecenas fermentum consequat mi. Donec fermentum. Pellentesque malesuada nulla a mi. Duis sapien sem, aliquet nec, commodo eget, consequat quis, neque. Aliquam faucibus, elit ut dictum aliquet, felis nisl adipiscing sapien, sed malesuada diam lacus eget erat. Cras mollis scelerisque nunc. Nullam arcu. Aliquam consequat. Curabitur augue lorem, dapibus quis, laoreet et, pretium ac, nisi. Aenean magna nisl, mollis quis, molestie eu, feugiat in, orci. In hac habitasse platea dictumst."
	//startUp = startUp + randomText + randomText + randomText + randomText + randomText

	termWidth, termHeight := ui.TerminalDimensions()

	logTextBox := widgets.NewParagraph()
	logTextBox.Title = startUp
	logTextBox.Text = waitMsg
	logTextBox.SetRect(0, 0, termWidth, termHeight)
	logTextBox.BorderStyle.Fg = ui.ColorBlue

	s := &ssh.Server{
		Addr: ":" + sPort,
		//Handler:         sessionHandler,
		PasswordHandler: passwordHandler,
	}
	log.SetFlags(0)

	fileName := "honeypot-" + time.Now().Format("2006-01-02") + ".log"
	logFile, err := os.Create(fileName)

	if err != nil {
		log.Fatal("Failed to create logfile")
	}
	defer logFile.Close()

	//mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(logFile)
	go s.ListenAndServe()

	ui.Render(logTextBox)

	uiEvents := ui.PollEvents()
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return

			case "<Resize>":
				payload := e.Payload.(ui.Resize)
				logTextBox.SetRect(0, 0, payload.Width, payload.Height)
				ui.Clear()
				ui.Render(logTextBox)
			}

		case msg := <-textUpdates:
			var loginData LoginData
			err := json.Unmarshal([]byte(msg), &loginData)

			if err != nil {
				logTextBox.Text = logTextBox.Text + "\n" + msg + " error: " + err.Error()
			} else {

				loginMsg := "[" + loginData.Date.Format(time.RFC3339) + "](fg:blue) - Login attempt from user: [" + loginData.User + "](fg:green)" + " with password: [" + loginData.Password + "](fg:red) from: [" + loginData.IPAddress + "](fg:yellow) [(" + loginData.City + ", " + loginData.Region + ", " + loginData.Country + ")](fg:yellow)"
				newText := logTextBox.Text + "\n" + loginMsg

				if countRune(newText, '\n') > logTextBox.Bounds().Dy()-3 {
					newText = trimToChar(newText, "\n")
				}
				logTextBox.Text = newText

			}

			ui.Render(logTextBox)
		}
	}

}

func countRune(s string, r rune) int {
	count := 0
	for _, c := range s {
		if c == r {
			count++
		}
	}
	return count
}

func trimToChar(s string, char string) string {
	if idx := strings.Index(s, char); idx != -1 {
		return s[idx+1:]
	}

	return s
}
