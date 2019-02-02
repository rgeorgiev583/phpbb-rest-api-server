package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/gocolly/colly"
)

type targetConfig struct {
	BaseURL string
}

type targetState struct {
	Collector *colly.Collector
}

type clientAuth struct {
	ExchangeKey string
	AuthKey     string
	SignKey     string
}

type clientState struct {
	Auth *clientAuth
}

type serverState struct {
	ClientsMutex sync.RWMutex
	Clients      map[string]*clientState
}

type responseBody struct {
	Status int         `json:"status"`
	Data   interface{} `json:"data"`
}

const nanosecsInMicrosec = 1000
const microsecsInSec = 1000000

var randomSeed string
var randomSeedLastUpdate int64
var wasSeeded bool

func microtime() string {
	var tv *syscall.Timeval
	syscall.Gettimeofday(tv)
	msec := tv.Usec / nanosecsInMicrosec
	sec := tv.Sec
	return fmt.Sprintf("%f %d", float64(msec)/microsecsInSec, sec)
}

func generateUniqueID(extra string) string {
	uniqueID := randomSeed + microtime()
	uniqueIDHashStr := fmt.Sprintf("%x", md5.Sum([]byte(uniqueID)))
	newRandomSeed := fmt.Sprintf("%x", md5.Sum([]byte(randomSeed+uniqueIDHashStr+extra)))
	if wasSeeded == false && randomSeedLastUpdate < time.Now().Unix()-int64(1+rand.Intn(11)) {
		randomSeedLastUpdate = time.Now().Unix()
		randomSeed = newRandomSeed
		wasSeeded = true
	}
	return uniqueIDHashStr[4:20] // blaze it
}

func generateDefaultUniqueID() string {
	return generateUniqueID("c")
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

	target := targetState{
		Collector: colly.NewCollector(),
	}

	target.Collector.OnResponse(func(response *colly.Response) {
		if response.Request.URL.Path == "/ucp.php" && response.Request.URL.Query().Get("mode") == "login" {
			switch response.StatusCode {
			case http.StatusOK:
				log.Printf("successfully logged into %s\n", response.Request.URL.Host)

			default:
				log.Printf("failed to log into %s: target responded with HTTP status code %d\n", response.Request.URL.Host, response.StatusCode)
			}
		}
	})

	server := serverState{
		Clients: make(map[string]*clientState),
	}

	http.HandleFunc("/auth/generate_keys", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("authorization request initiated by %s\n", request.RemoteAddr)
		log.Printf("generating authentication key triple for %s...\n", request.RemoteAddr)

		client := clientState{
			Auth: &clientAuth{
				ExchangeKey: generateDefaultUniqueID(),
				AuthKey:     generateDefaultUniqueID(),
				SignKey:     generateDefaultUniqueID(),
			},
		}

		server.ClientsMutex.Lock()
		server.Clients[request.RemoteAddr] = &client
		server.ClientsMutex.Unlock()

		data := map[string]string{
			"exchange_key": client.Auth.ExchangeKey,
		}
		response := responseBody{
			Status: 200,
			Data:   data,
		}
		responseText, err := json.Marshal(response)
		if err != nil {
			log.Printf("authorization request by %s failed: could not serialize response data to JSON: %s\n", request.RemoteAddr, err.Error())
			return
		}

		_, err = writer.Write(responseText)
		if err != nil {
			log.Printf("authorization request by %s failed: could not send serialized response data: %s\n", request.RemoteAddr, err.Error())
			return
		}
	})

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

		err := target.Collector.Post(config.BaseURL+"/ucp.php?mode=login", map[string]string{
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
