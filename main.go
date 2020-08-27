package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/viper"
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

func main() {
	var folder string
	flag.StringVar(&folder, "f", ".", "Scan a folder.")
	flag.Parse()

	if folder == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	resp, err := http.Get("https://gist.githubusercontent.com/toufik-airane/93336cc01c99f9044b4565cb5ec363f0/raw/config.yml")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	viper.SetConfigType("yaml")
	viper.ReadConfig(bytes.NewBuffer(body))
	fmt.Println(viper.Get("secrets"))

	var secrets map[string]string

	secrets = viper.GetStringMapString("secrets")

	patterns := make(map[string]*regexp.Regexp)

	for key, value := range secrets {
		patterns[key] = regexp.MustCompile(value)
	}

	walkPath(folder, patterns)

}

func walkPath(filename string, patterns map[string]*regexp.Regexp) {
	filepath.Walk(filename,
		func(path string, file os.FileInfo, err error) error {
			if !file.IsDir() {
				readFile(path, patterns)
			}
			return nil
		})
}

func readFile(filename string, patterns map[string]*regexp.Regexp) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	searchText(data, patterns, filename)

}

func searchText(data []byte, patterns map[string]*regexp.Regexp, filename string) {
	filter := regexp.MustCompile("[[:^ascii:]]")
	data = filter.ReplaceAll(data, []byte(""))

	for key, value := range patterns {
		matches := value.FindAllString(string(data), -1)
		for _, value := range matches {
			fmt.Printf(white+" "+red+" "+white+"\n", filename, key, value)
		}
	}
}
