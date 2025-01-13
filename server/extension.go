package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"time"
	"flag"

	"github.com/osquery/osquery-go"
)

const (
	ExitString = "exit"
)

type Query struct {
	SQL string `json:"query"`
}

type Result struct {
	Data interface{} `json:"data"`
}

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
)

var logger *log.Logger

func main() {
    f, err := os.OpenFile("/tmp/osquery_extension.log", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	logger = log.New(f, "osquery.json_extension", log.LstdFlags)

	flag.Parse()
	if *socket == "" {
		logger.Fatalln("Missing required --socket argument")
	}

	client, err := osquery.NewClient(*socket, 10*time.Second)
	if err != nil {
		logger.Fatalf("Error creating extension: %s\n", err)
	}
	defer client.Close()

	for {
		query, err := decodeQuery()
		if err != nil {
			if err == io.EOF {
				logger.Println("client has disconnected")
				break
			}
			logger.Fatalf("Error decoding JSON: %v\n", err)
		}

		logger.Printf("received query: %v", query)

		if query.SQL == ExitString {
			logger.Println("Exit command received, terminating...")
			break
		}

		resp, err := client.Query(query.SQL)
		if err != nil {
			logger.Fatalf("Error communicating with osqueryi: %v", err)
		}
		if resp.Status.Code != 0 {
			logger.Printf("osqueryi returned error: %s", resp.Status.Message)
		}

		err = parseAndSendResult(resp.Response)
		if err != nil {
			logger.Fatalf("Error parsing and sending result: %v\n", err)
		}
	}
}

func decodeQuery() (*Query, error) {
	decoder := json.NewDecoder(os.Stdin)
	query := &Query{}
	err := decoder.Decode(query)

	return query, err
}

func parseAndSendResult(respData interface{}) error {
	// Create Result with JSON data
	result := &Result{
		Data: respData,
	}
 
	// Send Result as JSON
	return json.NewEncoder(os.Stdout).Encode(result)
}
