package main

import (
	"bytes"
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
	"regexp"
	"strconv"
	"sync"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

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

var forumIDMatcher = regexp.MustCompile(`\./viewforum\.php\?f=(\d+)`)
var topicIDMatcher = regexp.MustCompile(`\./viewtopic\.php\?f=\d+&t=(\d+)`)

func newClient() (client *clientState, err error) {
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
		AuthMap: map[string]*clientState{},
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

		client, err := newClient()
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

	router.HandleFunc("/forums", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("attempting to retrieve the list of forums at `%s` by `%s`...\n", configName, request.RemoteAddr)

		accessToken := request.FormValue("access_token")
		if accessToken == "" {
			log.Printf("failed to retrieve the list of forums at `%s` by `%s`: no access token provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		server.Mutex.Lock()
		client, isLoggedIn := server.AuthMap[accessToken]
		server.Mutex.Unlock()
		if !isLoggedIn {
			log.Printf("failed to retrieve the list of forums at `%s` by `%s`: client with access token `%s` is not logged in\n", configName, request.RemoteAddr, accessToken)
			return
		}

		serverResponse, err := client.Get(config.BaseURL)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user with access token `%s`: could not initiate GET request: %s\n", configName, accessToken, err.Error())
			return
		}
		defer serverResponse.Body.Close()

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)

		document, err := html.Parse(serverResponse.Body)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user `%s`: could not parse index HTML page: %s\n", configName, accessToken, err.Error())
			return
		}

		forumLinks := scrape.FindAll(document, scrape.ByClass("forumlink"))
		response := make([]map[string]interface{}, len(forumLinks))

		for i, forumLink := range forumLinks {
			forumMetadata := map[string]interface{}{}

			var forumURL string
			for _, attr := range forumLink.Attr {
				if atom.Lookup([]byte(attr.Key)) == atom.Href {
					forumURL = attr.Val
				}
			}
			if forumURL == "" {
				log.Printf("warning: found forum link with empty URL for forum with index %d; skipping...\n", i)
				continue
			}

			forumIDMatches := forumIDMatcher.FindStringSubmatch(forumURL)
			forumMetadata["id"] = forumIDMatches[1]

			forumLinkText := forumLink.FirstChild
			if forumLinkText == nil || forumLinkText.Type != html.TextNode {
				log.Printf("warning: could not find name of forum with index %d\n", i)
				continue
			}
			forumMetadata["name"] = forumLinkText.Data

			response[i] = forumMetadata
		}

		forumDescriptions := scrape.FindAll(document, scrape.ByClass("forumdesc"))
		for i := 0; i < len(response) && i < len(forumDescriptions); i++ {
			forumDescriptionText := forumDescriptions[i].FirstChild
			if forumDescriptionText == nil || forumDescriptionText.Type != html.TextNode {
				log.Printf("warning: could not find description of forum with index %d\n", i)
				continue
			}
			response[i]["description"] = forumDescriptionText.Data
		}

		responseText, err := json.Marshal(response)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user with access token `%s`: could not serialize response data to JSON: %s\n", configName, accessToken, err.Error())
			return
		}

		_, err = writer.Write(responseText)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user with access token `%s`: could not send serialized response data: %s\n", configName, accessToken, err.Error())
			return
		}
	})

	router.HandleFunc("/topics/{forumID}", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("attempting to retrieve list of topics at `%s` by `%s`...\n", configName, request.RemoteAddr)

		accessToken := request.FormValue("access_token")
		if accessToken == "" {
			log.Printf("failed to retrieve list of topics at `%s` by `%s`: no access token provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		forumID, ok := mux.Vars(request)["forumID"]
		if !ok {
			log.Printf("failed to retrieve list of topics at `%s` by `%s`: no forum ID provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		server.Mutex.Lock()
		client, isLoggedIn := server.AuthMap[accessToken]
		server.Mutex.Unlock()
		if !isLoggedIn {
			log.Printf("failed to retrieve list of topics at `%s` by `%s`: client with access token `%s` is not logged in\n", configName, request.RemoteAddr, accessToken)
			return
		}

		serverResponse, err := client.Get(config.BaseURL + "/viewforum.php?f=" + forumID)
		if err != nil {
			log.Printf("failed to retrieve list of topics at `%s` by user with access token `%s`: could not initiate GET request: %s\n", configName, accessToken, err.Error())
			return
		}
		defer serverResponse.Body.Close()

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)

		document, err := html.Parse(serverResponse.Body)
		if err != nil {
			log.Printf("failed to retrieve list of topics at `%s` by user `%s`: could not parse index HTML page: %s\n", configName, accessToken, err.Error())
			return
		}

		topicLinks := scrape.FindAll(document, scrape.ByClass("topictitle"))
		response := make([]map[string]interface{}, len(topicLinks))

		for i, topicLink := range topicLinks {
			topicMetadata := map[string]interface{}{}

			var topicURL string
			for _, attr := range topicLink.Attr {
				if atom.Lookup([]byte(attr.Key)) == atom.Href {
					topicURL = attr.Val
				}
			}
			if topicURL == "" {
				log.Printf("warning: found topic link with empty URL for topic with index %d; skipping...\n", i)
				continue
			}

			topicIDMatches := topicIDMatcher.FindStringSubmatch(topicURL)
			topicMetadata["id"] = topicIDMatches[1]

			topicLinkText := topicLink.FirstChild
			if topicLinkText == nil || topicLinkText.Type != html.TextNode {
				log.Printf("warning: could not find name of topic with index %d\n", i)
				continue
			}
			topicMetadata["name"] = topicLinkText.Data

			response[i] = topicMetadata
		}

		responseText, err := json.Marshal(response)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user with access token `%s`: could not serialize response data to JSON: %s\n", configName, accessToken, err.Error())
			return
		}

		_, err = writer.Write(responseText)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user with access token `%s`: could not send serialized response data: %s\n", configName, accessToken, err.Error())
			return
		}
	})

	router.HandleFunc("/posts/{forumID}/{topicID}/{pageNumber}", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("attempting to retrieve list of posts at `%s` by `%s`...\n", configName, request.RemoteAddr)

		accessToken := request.FormValue("access_token")
		if accessToken == "" {
			log.Printf("failed to retrieve list of posts at `%s` by `%s`: no access token provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		vars := mux.Vars(request)

		forumID, ok := vars["forumID"]
		if !ok {
			log.Printf("failed to retrieve list of posts at `%s` by `%s`: no forum ID provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		topicID, ok := vars["topicID"]
		if !ok {
			log.Printf("failed to retrieve list of posts at `%s` by `%s`: no topic ID provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		pageNumberStr, ok := vars["pageNumber"]
		if !ok {
			log.Printf("failed to retrieve list of posts at `%s` by `%s`: no page number provided\n", configName, request.RemoteAddr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		pageNumber, err := strconv.Atoi(pageNumberStr)
		if err != nil {
			log.Printf("failed to retrieve list of posts at `%s` by `%s`: could not parse page number\n", configName, request.RemoteAddr)
			return
		}
		if pageNumber < 1 {
			log.Printf("failed to retrieve list of posts at `%s` by `%s`: page number must be a positive integer\n", configName, request.RemoteAddr)
			return
		}

		server.Mutex.Lock()
		client, isLoggedIn := server.AuthMap[accessToken]
		server.Mutex.Unlock()
		if !isLoggedIn {
			log.Printf("failed to retrieve list of posts at `%s` by `%s`: client with access token `%s` is not logged in\n", configName, request.RemoteAddr, accessToken)
			return
		}

		serverResponse, err := client.Get(config.BaseURL + "/viewtopic.php?f=" + forumID + "&t=" + topicID + "&start=" + strconv.Itoa(15*(pageNumber-1)))
		if err != nil {
			log.Printf("failed to retrieve list of posts at `%s` by user with access token `%s`: could not initiate GET request: %s\n", configName, accessToken, err.Error())
			return
		}
		defer serverResponse.Body.Close()

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)

		document, err := html.Parse(serverResponse.Body)
		if err != nil {
			log.Printf("failed to retrieve list of posts at `%s` by user `%s`: could not parse index HTML page: %s\n", configName, accessToken, err.Error())
			return
		}

		postBodies := scrape.FindAll(document, scrape.ByClass("postbody"))
		response := make([]map[string]interface{}, 0, len(postBodies))

		for i, postBody := range postBodies {
			if postBody.DataAtom != atom.Div {
				continue
			}

			post := map[string]interface{}{}

			var postTextBuffer bytes.Buffer
			for postBodyChildElement := postBody.FirstChild; postBodyChildElement != nil; postBodyChildElement = postBodyChildElement.NextSibling {
				err := html.Render(&postTextBuffer, postBodyChildElement)
				if err != nil {
					log.Printf("warning: could not render body of post with index %d\n", i)
					continue
				}
			}
			post["body"] = postTextBuffer.String()

			response = append(response, post)
		}

		postSignatures := scrape.FindAll(document, scrape.ByClass("signature"))
		for i := 0; i < len(response) && i < len(postSignatures); i++ {
			var postSignatureTextBuffer bytes.Buffer
			postSignature := postSignatures[i]
			for postSignatureChildElement := postSignature.FirstChild; postSignatureChildElement != nil; postSignatureChildElement = postSignatureChildElement.NextSibling {
				err := html.Render(&postSignatureTextBuffer, postSignatureChildElement)
				if err != nil {
					log.Printf("warning: could not render signature of post with index %d\n", i)
					continue
				}
			}
			response[i]["signature"] = postSignatureTextBuffer.String()
		}

		postAuthors := scrape.FindAll(document, scrape.ByClass("postauthor"))
		for i := 0; i < len(response) && i < len(postAuthors); i++ {
			postAuthorName := postAuthors[i].FirstChild
			if postAuthorName == nil || postAuthorName.Type != html.TextNode {
				log.Printf("warning: could not find author of post with index %d\n", i)
				continue
			}
			response[i]["author"] = postAuthorName.Data
		}

		responseText, err := json.Marshal(response)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user with access token `%s`: could not serialize response data to JSON: %s\n", configName, accessToken, err.Error())
			return
		}

		_, err = writer.Write(responseText)
		if err != nil {
			log.Printf("failed to retrieve the list of forums at `%s` by user with access token `%s`: could not send serialized response data: %s\n", configName, accessToken, err.Error())
			return
		}
	})

	http.Handle("/", router)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
