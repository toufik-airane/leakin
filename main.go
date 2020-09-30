package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/viper"
	"github.com/tidwall/limiter"
)

const (
	black   = "\033[30m%s\033[0m"
	red     = "\033[31m%s\033[0m"
	green   = "\033[32m%s\033[0m"
	yellow  = "\033[33m%s\033[0m"
	blue    = "\033[34m%s\033[0m"
	magenta = "\033[35m%s\033[0m"
	cyan    = "\033[36m%s\033[0m"
	white   = "\033[97m%s\033[0m"
)

type config struct {
	Title  string `json:"title"`
	Checks []struct {
		Title    string         `json:"title"`
		Regex    string         `json:"regex"`
		Compiled *regexp.Regexp `json:"compiled"`
		Severity int            `json:"severity"`
	} `json:"checks"`
}

func main() {
	var folder string
	var limit int
	flag.StringVar(&folder, "f", ".", "Scan a folder.")
	flag.IntVar(&limit, "l", 10, "Limit of go routine.")
	flag.Parse()

	if folder == "" || limit < 0 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	viper.SetConfigType("json")
	viper.ReadConfig(bytes.NewBuffer(configbyte))

	var config config
	var err error

	err = viper.Unmarshal(&config)
	if err != nil {
		panic(err)
	}

	for index := range config.Checks {
		config.Checks[index].Compiled = regexp.MustCompile(config.Checks[index].Regex)
	}

	walkPath(folder, config, limit)
}

func walkPath(root string, config config, limit int) {
	goroutine := limiter.New(limit)

	filepath.Walk(root,
		func(path string, file os.FileInfo, err error) error {
			if !file.IsDir() {
				goroutine.Begin()
				defer goroutine.End()
				readFile(path, config)
			}
			return nil
		})
}

func readFile(filename string, config config) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	searchText(filename, data, config)
}

var filter = regexp.MustCompile("[[ascii]]")

func searchText(filename string, data []byte, config config) {
	data = filter.ReplaceAll(data, []byte(""))
	for _, check := range config.Checks {
		matches := check.Compiled.FindAll(data, -1)
		for _, match := range matches {
			fmt.Printf(blue+" "+white+" "+red+"\n", filename, check.Title, match)
		}
	}
}
