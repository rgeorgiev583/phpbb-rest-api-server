package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"sync"

	"github.com/gorilla/mux"

	"github.com/BurntSushi/toml"
)

type serverConfig struct {
	BaseURL string
}

type clientState struct {
	http.Client
}

type serverState struct {
	Mutex   sync.RWMutex
	Clients map[string]*clientState // map from the username of the client to its correspoding clientState instance
}

func newClient(server *serverState) (client *clientState, err error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return
	}

	client = &clientState{
		Client: http.Client{Jar: cookieJar},
	}
	return
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
		client, err := newClient(server)
		if err != nil {
			log.Printf("failed to log into `%s` from %s with username `%s`: could not initialize HTTP client: %s\n", configName, request.RemoteAddr, username, err.Error())
			return
		}

		func() {
			server.Mutex.Lock()
			defer server.Mutex.Unlock()

			_, isAlreadyLoggedIn := server.Clients[username]
			if isAlreadyLoggedIn {
				log.Printf("failed to log into `%s` from %s: client with username `%s` is already logged in\n", configName, request.RemoteAddr, username)
				return
			}

			server.Clients[username] = client
		}()

		params := url.Values{
			"username": usernames,
			"password": passwords,
			"login":    []string{"Влез"},
		}
		serverResponse, err := client.PostForm(config.BaseURL+"/ucp.php?mode=login", params)
		if err != nil {
			log.Printf("failed to log into `%s` from %s with username `%s`: could not initiate POST request: %s\n", configName, request.RemoteAddr, username, err.Error())
			return
		}
		defer serverResponse.Body.Close()

		writer.WriteHeader(serverResponse.StatusCode)

		response := make(map[string]interface{})
		if serverResponse.StatusCode == http.StatusOK {
			log.Printf("successfully logged into `%s` from %s with username `%s`\n", configName, request.RemoteAddr, username)
			response["success"] = true

			token := make([]byte, 16)
			_, err = rand.Read(token)
			if err != nil {
				log.Printf("failed to log into `%s` from %s with username `%s`: could not generate API access token: %s\n", configName, request.RemoteAddr, username, err.Error())
				return
			}

			hexToken := hex.EncodeToString(token)
			response["access_token"] = hexToken
		} else {
			log.Printf("failed to log into %s from %s with username `%s`: server responded with HTTP status code %d\n", configName, request.RemoteAddr, username, serverResponse.StatusCode)
			response["success"] = false
		}

		responseText, err := json.Marshal(response)
		if err != nil {
			log.Printf("failed to log into `%s` from %s with username `%s`: could not serialize response data to JSON: %s\n", configName, request.RemoteAddr, username, err.Error())
			return
		}

		_, err = writer.Write(responseText)
		if err != nil {
			log.Printf("failed to log into `%s` from %s with username `%s`: could not send serialized HTTP response data: %s\n", configName, request.RemoteAddr, username, err.Error())
			return
		}
	})

	http.Handle("/", router)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
