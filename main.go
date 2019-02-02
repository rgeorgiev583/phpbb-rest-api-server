package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/BurntSushi/toml"

	"github.com/gocolly/colly"
)

type targetConfig struct {
	BaseURL string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "error: no valid targets provided")
		fmt.Fprintf(os.Stderr, "usage: %s TARGET...", os.Args[0])
		return
	}

	configFilename := os.Args[1]
	configName := path.Base(configFilename)

	configFileContent, err := ioutil.ReadFile(configFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not init API server for target %s: could not read contents of target config file: %s\n", configName, err.Error())
		return
	}

	var config targetConfig
	_, err = toml.Decode(string(configFileContent), &config)
	if err != nil {
		log.Printf("error: could not init API server for target %s: could not decode contents of target config file: %s\n", configName, err.Error())
		return
	}

	collector := colly.NewCollector()

	http.HandleFunc("/x/auth/login", func(writer http.ResponseWriter, request *http.Request) {
		log.Println("login request arrived from", request.RemoteAddr)

		request.ParseForm()

		usernames, ok := request.Form["username"]
		if !ok || len(usernames) < 1 {
			log.Printf("login request from %s failed: no username provided\n", request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		} else if len(usernames) > 1 {
			log.Printf("login request from %s failed: too many usernames provided\n", request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		passwords, ok := request.Form["password"]
		if !ok || len(passwords) < 1 {
			log.Printf("login request from %s failed: no password provided\n", request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		} else if len(passwords) > 1 {
			log.Printf("login request from %s failed: too many passwords provided\n", request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		username := usernames[0]
		password := passwords[0]

		err := collector.Post(config.BaseURL+"/ucp.php?mode=login", map[string]string{
			"username": username,
			"password": password,
			"login":    "Влез",
		})
		if err != nil {
			log.Printf("login request from %s to target %s failed: could not authenticate to target: failed to initiate POST request: %s\n", request.RemoteAddr, configName, err.Error())
			return
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
