package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/gorilla/mux"

	"github.com/BurntSushi/toml"

	"github.com/gocolly/colly"
)

type serverConfig struct {
	BaseURL string
}

type clientState struct {
	Collector *colly.Collector
}

type serverState struct {
	Mutex   sync.RWMutex
	Clients map[string]*clientState // map from the username of the client to its correspoding clientState instance
}

func newCollector(server *serverState) *colly.Collector {
	collector := colly.NewCollector()
	collector.OnResponse(func(response *colly.Response) {
		if response.Request.URL.Path == "/ucp.php" && response.Request.URL.Query().Get("mode") == "login" {
			serverName := response.Ctx.Get("server_name")
			remoteAddr := response.Ctx.Get("remote_addr")
			username := response.Ctx.Get("username")
			if serverName == "" || remoteAddr == "" || username == "" {
				panic(fmt.Sprintln("fatal: no server name or remote address or username specified in login request context"))
			}

			switch response.StatusCode {
			case http.StatusOK:
				log.Printf("successfully logged into `%s` from %s with username `%s`\n", serverName, remoteAddr, username)
				response.Ctx.Put("success", true)

			default:
				log.Printf("failed to log into %s from %s with username `%s`: server responded with HTTP status code %d\n", serverName, remoteAddr, username, response.StatusCode)
				response.Ctx.Put("success", false)
			}
		}
	})
	return collector
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

	var config serverConfig
	_, err = toml.Decode(string(configFileContent), &config)
	if err != nil {
		log.Printf("error: could not init API server for target %s: could not decode contents of target config file: %s\n", configName, err.Error())
		return
	}

	server := &serverState{
		Clients: make(map[string]*clientState),
	}

	router := mux.NewRouter()

	router.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("attempting to log into `%s` from %s...\n", configName, request.RemoteAddr)

		request.ParseForm()

		usernames, ok := request.Form["username"]
		if !ok || len(usernames) < 1 {
			log.Printf("failed to log into `%s` from %s: no username provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		} else if len(usernames) > 1 {
			log.Printf("failed to log into `%s` from %s: too many usernames provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		passwords, ok := request.Form["password"]
		if !ok || len(passwords) < 1 {
			log.Printf("failed to log into `%s` from %s: no password provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		} else if len(passwords) > 1 {
			log.Printf("failed to log into `%s` from %s: too many passwords provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		username := usernames[0]
		collector := newCollector(server)

		func() {
			server.Mutex.Lock()
			defer server.Mutex.Unlock()

			_, isAlreadyLoggedIn := server.Clients[username]
			if isAlreadyLoggedIn {
				log.Printf("failed to log into `%s` from %s: client with username `%s` is already logged in\n", configName, request.RemoteAddr, username)
				return
			}

			server.Clients[username] = &clientState{
				Collector: collector,
			}
		}()

		params := url.Values{
			"username": usernames,
			"password": passwords,
			"login":    []string{"Влез"},
		}
		encodedParams := params.Encode()
		encodedParamsReader := strings.NewReader(encodedParams)
		context := colly.NewContext()
		context.Put("server_name", configName)
		context.Put("remote_addr", request.RemoteAddr)
		context.Put("username", username)
		err := collector.Request(http.MethodPost, config.BaseURL+"/ucp.php?mode=login", encodedParamsReader, context, nil)
		if err != nil {
			log.Printf("failed to log into `%s` from %s with username `%s`: could not initiate POST request: %s\n", configName, request.RemoteAddr, username, err.Error())
			return
		}

		ok = context.GetAny("success").(bool)
		if ok {
			writer.WriteHeader(http.StatusOK)
		} else {
			writer.WriteHeader(http.StatusForbidden)
		}
	})

	http.Handle("/", router)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
