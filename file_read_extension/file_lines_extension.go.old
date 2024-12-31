package main

import (
	"log"
	"flag"
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	//"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

type FileLine struct {
	Line string
	Path string
}

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"file_lines",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewPlugin("file_lines", FileLineColumns(), FileLineGenerate))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func FileLineColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("line"),
		table.TextColumn("path"),
	}
}

func FileLineGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	path := ""
	wildcard := false

	if constraintList, present := queryContext.Constraints["path"]; present {
		// 'path' is in the where clause
		for _, constraint := range constraintList.Constraints {
			// LIKE
			if constraint.Operator == table.OperatorLike {
				path = constraint.Expression
				wildcard = true
			}
			// =
			if constraint.Operator == table.OperatorEquals {
				path = constraint.Expression
				wildcard = false
			}
		}
	}
	var results []map[string]string
	output, err := processFile(path, wildcard)
	if err != nil {
		return results, err
	}

	for _, item := range output {
		results = append(results, map[string]string{
			"line": item.Line,
			"path": item.Path,
		})
	}

	return results, nil
}

func processFile(path string, wildcard bool) ([]FileLine, error) {
    var output []FileLine

    if wildcard {
        replacedPath := strings.ReplaceAll(path, "%", "*")

        files, err := filepath.Glob(replacedPath)
        if err != nil {
            return nil, err
        }
        for _, file := range files {
            lines, err := readLines(file)
            if err != nil {
                return nil, err // Return the error here if reading the file fails
            }
            output = append(output, lines...)
        }
    } else {
        lines, err := readLines(path)
        if err != nil {
            return nil, err // Return the error here if reading the file fails
        }
        output = append(output, lines...)
    }

    return output, nil
}


func readLines(path string) ([]FileLine, error) {
	var output []FileLine

	if !fileExists(path) {
		err := errors.New("File does not exist")
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		item := FileLine{Path: path, Line: line}
		output = append(output, item)
	}

	if scanner.Err() != nil {
		fmt.Printf("error: %s\n", scanner.Err())
	}

	return output, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}