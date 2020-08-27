package main

import (
	"flag"
	"fmt"
	"io/ioutil"
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
	var root string
	flag.StringVar(&root, "r", ".", "Root folder.")
	flag.Parse()

	secrets := getConfig().Secrets
	patterns := make(map[string]*regexp.Regexp)

	for key, value := range secrets {
		patterns[key] = regexp.MustCompile(value)
	}

	walkPath(root, patterns)
}

func getConfig() configType {

	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("https://github.com/test")

	return viper.Get("secrets")
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
