package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

const (
	black   = "\033[30m%s\033[0m"
	red     = "\033[31m%s\033[0m"
	green   = "\033[32m%s\033[0m"
	yellow  = "\033[33m%s\033[0m"
	blue    = "\033[34m%s\033[0m"
	blueint = "\033[34m%d\033[0m"
	magenta = "\033[35m%s\033[0m"
	cyan    = "\033[36m%s\033[0m"
	white   = "\033[97m%s\033[0m"
)

func main() {
	config := getConfig().Secrets
	patterns := make(map[string]*regexp.Regexp)

	for key, value := range config {
		patterns[key] = regexp.MustCompile(value)
	}

	walkPath(os.Args[1], patterns)
}

func getConfig() config {
	var config config

	err := yaml.Unmarshal([]byte(secrets), &config)
	if err != nil {
		panic(err)
	}

	return config
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
			fmt.Printf(blue+" "+red+" "+yellow+"\n", filename, key, value)
		}
	}
}
