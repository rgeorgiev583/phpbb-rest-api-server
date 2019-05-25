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

	"golang.org/x/net/html"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/yhat/scrape"
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
	AuthMap map[string]*clientState // map from the access token for the client to its correspoding clientState instance
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
		fmt.Fprintln(os.Stderr, "error: no valid target provided")
		fmt.Fprintf(os.Stderr, "usage: %s TARGET", os.Args[0])
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
		Clients: map[string]*clientState{},
	}

	router := mux.NewRouter()

	router.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("attempting to log into `%s` from %s...\n", configName, request.RemoteAddr)

		request.ParseForm()

		username := request.Form.Get("username")
		if username == "" {
			log.Printf("failed to log into `%s` from %s: no username provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		password := request.Form.Get("password")
		if password == "" {
			log.Printf("failed to log into `%s` from %s: no password provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		client, err := newClient(server)
		if err != nil {
			log.Printf("failed to log into `%s` from %s with username `%s`: could not initialize HTTP client: %s\n", configName, request.RemoteAddr, username, err.Error())
			return
		}

		params := url.Values{}
		params.Set("username", username)
		params.Set("password", password)
		params.Set("login", "Влез")
		serverResponse, err := client.PostForm(config.BaseURL+"/ucp.php?mode=login", params)
		if err != nil {
			log.Printf("failed to log into `%s` from %s with username `%s`: could not initiate POST request: %s\n", configName, request.RemoteAddr, username, err.Error())
			return
		}
		defer serverResponse.Body.Close()

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(serverResponse.StatusCode)

		response := map[string]interface{}{}
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

			func() {
				server.Mutex.Lock()
				defer server.Mutex.Unlock()

				_, isAlreadyLoggedIn := server.Clients[username]
				if isAlreadyLoggedIn {
					log.Printf("failed to log into `%s` from %s: client with username `%s` is already logged in\n", configName, request.RemoteAddr, username)
					return
				}

				server.Clients[username] = client
				server.AuthMap[hexToken] = client
			}()
		} else {
			log.Printf("failed to log into %s from %s with username `%s`: server responded with HTTP status code %d\n", configName, request.RemoteAddr, username, serverResponse.StatusCode)
			response["success"] = false

			func() {
				document, err := html.Parse(serverResponse.Body)
				if err != nil {
					log.Printf("warning: could not parse HTML page for failed login\n")
					return
				}

				errNode, ok := scrape.Find(document, scrape.ByClass("error"))
				if !ok {
					log.Printf("warning: could not find error text in HTML page for failed login\n")
					return
				}

				errText := errNode.FirstChild
				if errText == nil || errText.Type != html.TextNode {
					log.Printf("warning: could not find text node for error text in HTML page for failed login\n")
				}

				response["error"] = errText.Data
			}()
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
