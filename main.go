package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

// apiKey represents the VirusTotal API key
var apiKey = "YOUR_API_KEY"

// Loggers
var (
	nullLogger   *log.Logger
	StrekkLogger *log.Logger
	InfoLogger   *log.Logger
	WarnLogger   *log.Logger
	ErrorLogger  *log.Logger
)

// Initialize loggers to stdout
func init() {
	nullLogger = log.New(os.Stdout, "        ", 0)
	StrekkLogger = log.New(os.Stdout, " ---------------------", 0)
	InfoLogger = log.New(os.Stdout, " [ + ] ", 0)
	WarnLogger = log.New(os.Stdout, " [ ! ] ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(os.Stdout, " [ - ] ", 0)
}

func main() {
	// Flag
	var version = flag.Bool("v", false, "Print version")
	var filename = flag.String("f", "", "File to calculate SHA256 checksum")
	var apikey = &apiKey
	flag.Parse()

	if *version == true {
		InfoLogger.Println("Name:              VirusTotal API v3 client")
		InfoLogger.Println("Version:           0.2.0")
		InfoLogger.Println("Author:            SpiX-777")
		InfoLogger.Println("eMail:             rufus777@gmail.com")
		os.Exit(0)
	}

	// Error handling
	if *filename == "" {
		ErrorLogger.Fatalln("Must pass the --file argument.")
	}

	if *apikey == "" {
		ErrorLogger.Fatalln("Must pass the --apikey argument.")
	}

	if len(*apikey) != 64 {
		ErrorLogger.Fatalln("Invalid API key.")
	}

	banner()
	// Check SHA256 checksum in a file and print it
	checksum := Sha256Sum(*filename)
	var sum = &checksum
	InfoLogger.Println("File:              ", *filename)
	InfoLogger.Println("SHA256 Checksum:   ", checksum)
	InfoLogger.Println("VirusTotal API key:", *apikey)
	// Check VirusTotal API key, SHA256 checksum, and scan result
	var end = 0
	virusTotal(sum, apikey, filename, end)
}

// banner prints the application banner
func banner() {
	banner := `
____   ____.__                    ___________     __         .__   
\   \ /   /|__|______ __ __  _____\__    ___/____/  |______  |  |  
 \   Y   / |  \_  __ \  |  \/  ___/ |    | /  _ \   __\__  \ |  |  
  \     /  |  ||  | \/  |  /\___ \  |    |(  <_> )  |  / __ \|  |__
   \___/   |__||__|  |____//____  > |____| \____/|__| (____  /____/
                                \/                         \/      	
								`
	nullLogger.Println(banner)
}

// Sha256Sum calculates the SHA256 checksum of a file
func Sha256Sum(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		ErrorLogger.Fatalln("Error opening file:", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		ErrorLogger.Fatalln("Error calculating SHA256 checksum:", err)
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	return checksum
}

// virusTotal checks VirusTotal API key, SHA256 checksum, and scan result
func virusTotal(sha256, apikey *string, filename *string, end int) {
	if *apikey == "" || *sha256 == "" {
		ErrorLogger.Fatalln("Must pass both the --apikey and --sha256 arguments.")
	}

	client := vt.NewClient(*apikey)

	file, err := client.GetObject(vt.URL("files/%s", *sha256))
	if err != nil {
		scanFile(sha256, apikey, filename, end)
	}

	ls, err := file.GetTime("last_submission_date")
	if err != nil {
		ErrorLogger.Fatalln(err)
	}
	url := "https://www.virustotal.com/gui/file/" + *sha256 + "/details"
	InfoLogger.Println("Date:               submitted for the last time on", ls)
	InfoLogger.Println("URL:               ", url)

	vt, err := file.Get("last_analysis_stats")
	if err != nil {
		ErrorLogger.Fatalln(err)
	}

	nullLogger.Println()
	InfoLogger.Println("Last Analysis Stats:")
	nullLogger.Println("Harmless:         ", vt.(map[string]interface{})["harmless"])
	nullLogger.Println("Malicious:        ", vt.(map[string]interface{})["malicious"])
	nullLogger.Println("Suspicious:       ", vt.(map[string]interface{})["suspicious"])
	nullLogger.Println("Undetected:       ", vt.(map[string]interface{})["undetected"])
	nullLogger.Println("Timeout:          ", vt.(map[string]interface{})["timeout"])
	nullLogger.Println("Type-unsupported: ", vt.(map[string]interface{})["type-unsupported"])
	nullLogger.Println("Failure:          ", vt.(map[string]interface{})["failure"])
	if end == 1 {
		os.Exit(0)
	}
}

// scanFile scans a file using VirusTotal API
func scanFile(sha256, apikey *string, filename *string, end int) {
	// Create the `curl` command
	cmd := exec.Command(
		"curl",
		"--request", "POST",
		"--url", "https://www.virustotal.com/api/v3/files",
		"--header", "accept: application/json",
		"--header", "content-type: multipart/form-data",
		"--header", "x-apikey: "+*apikey,
		"--form", "file=@"+*filename,
	)

	// Run the command and capture the output
	out, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	// Convert the output to a string
	outputString := string(out)
	i := strings.Split(outputString, "id")
	InfoLogger.Println("Scan ID:           ", i[1][4:64])

	// Create the `curl` command
	cmd = exec.Command(
		"curl",
		"--request", "GET",
		"--url", "https://www.virustotal.com/api/v3/analyses/"+i[1][4:64],
		"--header", "x-apikey: "+*apikey,
	)

	// Capture the command output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	// Convert the output to a string
	outputString = string(output)
	time.Sleep(60 * time.Second)
	end = 1
	virusTotal(sha256, apikey, filename, end)
}
