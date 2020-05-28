package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"strings"
	"time"

	// Needed to get at the ParsePrivateKey function. There must be a better way to do this?
	gossh "golang.org/x/crypto/ssh"

	"github.com/gliderlabs/ssh"
	"github.com/oschwald/geoip2-golang"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// Channel for updates from the handlers to the TUI
var textUpdates chan string

// LoginData is the internal representation of my json object created when someone
// attempts a login
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
	//TODO: I think I can redo the geolocation error logic. There are lots of failure cases resulting in the same output.

	jsonOutput := "{}"
	isMMDB := true

	city := "Unknown City"
	region := "Unknown Region"
	country := "Unknwon Country"

	lat := "0"
	long := "0"

	// Get Location information
	cityDb, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		isMMDB = false
	}

	ipAddr := strings.Split(ctx.RemoteAddr().String(), ":")[0]
	if isMMDB {
		defer cityDb.Close()

		if ipAddr == "127.0.0.1" {
			// If we are testing from localhost, "fake" an IP address to test geolocation
			//ipAddr = "216.58.204.238"
			ipAddr = "85.209.0.100"
		}

		// If you are using strings that may be invalid, check that ip is not nil
		ip := net.ParseIP(ipAddr)
		record, err := cityDb.City(ip)
		if err != nil {
			// If we dont find a valid record in the DB, default to "Unknown" for the geolocation data.
			jsonOutput = "{\"date\": \"" + time.Now().Format(time.RFC3339) + "\",\"user\": \"" + ctx.User() + "\", \"password\": \"" + password + "\", \"ip_address\": \"" + ipAddr + "\",\"city\": \"Unknown City\", \"region\": \"Unknown Region\", \"country\": \"Unknown Country\",\"latitude\":0,\"longitude\":0}"
		} else {

			if len(record.City.Names) > 0 {
				city = record.City.Names["en"]
			}

			if len(record.Subdivisions) > 0 {
				region = record.Subdivisions[0].Names["en"]
			}

			if len(record.Country.Names) > 0 {
				country = record.Country.Names["en"]
			}

			lat = fmt.Sprintf("%f", record.Location.Latitude)
			long = fmt.Sprintf("%f", record.Location.Longitude)

		}
	}

	jsonOutput = "{\"date\": \"" + time.Now().Format(time.RFC3339) + "\",\"user\": \"" + ctx.User() + "\", \"password\": \"" + password + "\", \"ip_address\": \"" + ipAddr + "\",\"city\": \"" + city + "\", \"region\": \"" + region + "\", \"country\": \"" + country + "\",\"latitude\":" + lat + ",\"longitude\":" + long + "}"

	// Send the output to the textUpdates channel for rendering on the TUI
	textUpdates <- jsonOutput

	// Log the output for indexing and external analysis
	log.Println(jsonOutput)
	// Put in a small delay as a "real" ssh server might have
	time.Sleep(2 * time.Second)
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
	uiHeaderRow := "[" + strPad("Date", 25, " ", "RIGHT") + " " + strPad("User", 21, " ", "RIGHT") + strPad("Password", 20, " ", "RIGHT") + " " + "IP Address and Location](fg:magenta)"

	termWidth, termHeight := ui.TerminalDimensions()

	logTextBox := widgets.NewParagraph()
	logTextBox.Title = startUp
	logTextBox.Text = uiHeaderRow
	logTextBox.SetRect(0, 0, termWidth, termHeight)
	logTextBox.BorderStyle.Fg = ui.ColorBlue

	// Load a hostkey so a new one isnt generated every time
	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := gossh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	s := &ssh.Server{
		Addr:            ":" + sPort,
		PasswordHandler: passwordHandler,
	}
	s.AddHostKey(private)

	log.SetFlags(0)

	fileName := "honeypot-" + time.Now().Format("2006-01-02") + ".log"
	logFile, err := os.Create(fileName)

	if err != nil {
		log.Fatal("Failed to create logfile")
	}
	defer logFile.Close()

	// Use the multiwriter to write to stdout and to a logfile if required.
	// Used in testing
	//mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(logFile)
	go s.ListenAndServe()

	//ui.Render(titleTextBox)
	ui.Render(logTextBox)

	uiEvents := ui.PollEvents()
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {

			// Quit when q is enterd
			case "q", "<C-c>":
				return

			// Adjust the UI boarder when the window is resized
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

				loginMsg := formatOutput(loginData)
				newText := logTextBox.Text + "\n" + loginMsg

				// If the output is about to fill the textbox, trim by one line.
				if countRune(newText, '\n') > logTextBox.Bounds().Dy()-3 {
					headerRow := "[" + strPad("Date", 25, " ", "RIGHT") + " " + strPad("User", 21, " ", "RIGHT") + strPad("Password", 20, " ", "RIGHT") + " " + "IP Address and Location](fg:magenta)\n"
					newText = headerRow + trimToChar(trimToChar(newText, "\n"), "\n")
				}
				logTextBox.Text = newText

			}

			ui.Render(logTextBox)
		}
	}

}

// Utilitiy function used to count the occurance of characters in a string.
// Used to count newlines to keep track of the number of lines in the output string
func countRune(s string, r rune) int {
	count := 0
	for _, c := range s {
		if c == r {
			count++
		}
	}
	return count
}

// Utility function that trims a string from the first occrance of a character.
// This is used to trim the output in the UI when it scrolls beyound the bounds of the textbox
func trimToChar(s string, char string) string {
	if idx := strings.Index(s, char); idx != -1 {
		return s[idx+1:]
	}

	return s
}

func formatOutput(raw LoginData) string {

	passwordFieldSize := 20
	userFieldSize := 20

	passwordText := strPad(raw.Password, passwordFieldSize, " ", "RIGHT")
	userText := strPad(raw.User, userFieldSize, " ", "RIGHT")

	output := "[" + raw.Date.Format(time.RFC3339) + "](fg:blue) [" + userText + "](fg:green) [" + passwordText + "](fg:red) [" + raw.IPAddress + "](fg:yellow) [(" + raw.City + ", " + raw.Region + ", " + raw.Country + ")](fg:yellow)"

	return output
}

// strPad pads a string byt the required length. From: https://gist.github.com/asessa/3aaec43d93044fc42b7c6d5f728cb039
func strPad(input string, padLength int, padString string, padType string) string {
	var output string

	inputLength := len(input)
	padStringLength := len(padString)

	if inputLength >= padLength {
		return input
	}

	repeat := math.Ceil(float64(1) + (float64(padLength-padStringLength))/float64(padStringLength))

	switch padType {
	case "RIGHT":
		output = input + strings.Repeat(padString, int(repeat))
		output = output[:padLength]
	case "LEFT":
		output = strings.Repeat(padString, int(repeat)) + input
		output = output[len(output)-padLength:]
	case "BOTH":
		length := (float64(padLength - inputLength)) / float64(2)
		repeat = math.Ceil(length / float64(padStringLength))
		output = strings.Repeat(padString, int(repeat))[:int(math.Floor(float64(length)))] + input + strings.Repeat(padString, int(repeat))[:int(math.Ceil(float64(length)))]
	}

	return output
}
