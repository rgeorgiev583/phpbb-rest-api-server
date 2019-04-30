package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"

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
	ExchangeKey  string
	AuthKey      string
	SignKey      string
	IsAuthorized bool
	Serial       uint
}

type clientState struct {
	Auth *clientAuth
}

type serverState struct {
	Mutex   sync.RWMutex
	Clients map[string]*clientState // map from auth keys to their correspoding clientState instances
	AuthMap map[string]*clientAuth  // map from exchange keys to their correspoding clientAuth instances
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

func authenticate(server *serverState, writer http.ResponseWriter, request *http.Request) (ok bool, err error) {
	authKeys, ok := request.Form["auth_key"]
	if !ok || len(authKeys) < 1 {
		log.Printf("authentication request from %s failed: no auth key provided\n", request.RemoteAddr)
		writer.WriteHeader(http.StatusBadRequest)
		return false, fmt.Errorf("no auth key provided")
	} else if len(authKeys) > 1 {
		log.Printf("authentication request from %s failed: too many auth keys provided\n", request.RemoteAddr)
		writer.WriteHeader(http.StatusBadRequest)
		return false, fmt.Errorf("too many auth keys provided")
	}

	serials, ok := request.Form["serial"]
	if !ok || len(serials) < 1 {
		log.Printf("login request from %s failed: no serial provided\n", request.RemoteAddr)
		writer.WriteHeader(http.StatusBadRequest)
		return false, fmt.Errorf("no serial provided")
	} else if len(serials) > 1 {
		log.Printf("login request from %s failed: too many serials provided\n", request.RemoteAddr)
		writer.WriteHeader(http.StatusBadRequest)
		return false, fmt.Errorf("too many serials provided")
	}

	hashes, ok := request.Form["hash"]
	if !ok || len(hashes) < 1 {
		log.Printf("authentication request from %s failed: no hash provided\n", request.RemoteAddr)
		writer.WriteHeader(http.StatusBadRequest)
		return false, fmt.Errorf("no hash provided")
	} else if len(hashes) > 1 {
		log.Printf("authentication request from %s failed: too many hashes provided\n", request.RemoteAddr)
		writer.WriteHeader(http.StatusBadRequest)
		return false, fmt.Errorf("too many hashes provided")
	}

	authKey := authKeys[0]
	serial := serials[0]
	hash := hashes[0]
	hashBinary, err := hex.DecodeString(hash)
	if err != nil {
		log.Printf("authentication request from %s failed: could not decode hash signature\n", request.RemoteAddr)
		return false, err
	}

	server.Mutex.Lock()

	clientAuth := server.Clients[authKey].Auth
	if !clientAuth.IsAuthorized {
		log.Printf("authentication request from %s failed: client with the provided auth key is not authorized\n", request.RemoteAddr)
		return false, fmt.Errorf("client with the provided auth key is not authorized")
	}

	requestString := request.URL.Path + "auth_key=" + authKey
	signKey := clientAuth.SignKey
	signKeyBinary, err := hex.DecodeString(signKey)
	if err != nil {
		log.Printf("authentication request from %s failed: could not decode signing key\n", request.RemoteAddr)
		return false, err
	}

	signer := hmac.New(sha256.New, signKeyBinary)
	signer.Write([]byte(requestString))
	validHashBinary := signer.Sum(nil)

	if string(hashBinary) != string(validHashBinary) {
		log.Printf("authentication request from %s failed: invalid hash signature\n", request.RemoteAddr)
		return false, fmt.Errorf("invalid hash signature")
	}

	serialNumber, err := strconv.ParseUint(serial, 10, 0)
	if err != nil {
		log.Printf("authentication request from %s failed: could not decode serial number\n", request.RemoteAddr)
		return false, err
	}
	serialNumberUint := uint(serialNumber)

	if serialNumberUint <= clientAuth.Serial {
		log.Printf("authentication request from %s failed: invalid serial\n", request.RemoteAddr)
		return false, fmt.Errorf("invalid serial")
	}

	clientAuth.Serial = serialNumberUint

	server.Mutex.Unlock()

	return true, nil
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

	server := serverState{
		Clients: make(map[string]*clientState),
		AuthMap: make(map[string]*clientAuth),
	}

	target.Collector.OnResponse(func(response *colly.Response) {
		if response.Request.URL.Path == "/ucp.php" && response.Request.URL.Query().Get("mode") == "login" {
			switch response.StatusCode {
			case http.StatusOK:
				log.Printf("successfully logged into %s\n", response.Request.URL.Host)

				exchangeKey := response.Ctx.Get("exchange_key")
				if exchangeKey == "" {
					log.Printf("failed to authorize %s: no exchange key was provided by the client\n", response.Request.URL.Host)
					return
				}

				remoteAddr := response.Ctx.Get("remote_addr")
				if remoteAddr == "" {
					log.Printf("failed to log into %s: could not identify the remote address of the client\n", response.Request.URL.Host)
					return
				}

				server.Mutex.Lock()
				auth, ok := server.AuthMap[exchangeKey]
				if !ok {
					log.Printf("authorization of exchange key provided by %s failed: exchange key not found in keymap\n", remoteAddr)
					return
				}
				auth.IsAuthorized = true
				server.Clients[auth.AuthKey] = &clientState{
					Auth: auth,
				}
				server.Mutex.Unlock()

			default:
				log.Printf("failed to log into %s: target responded with HTTP status code %d\n", response.Request.URL.Host, response.StatusCode)
			}
		}
	})

	router := mux.NewRouter()

	router.HandleFunc("/auth/generate_keys", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("authorization request initiated by %s\n", request.RemoteAddr)
		log.Printf("generating authentication key triple for %s...\n", request.RemoteAddr)

		auth := &clientAuth{
			ExchangeKey: generateDefaultUniqueID(),
			AuthKey:     generateDefaultUniqueID(),
			SignKey:     generateDefaultUniqueID(),
		}

		server.Mutex.Lock()
		server.AuthMap[auth.ExchangeKey] = auth
		server.Mutex.Unlock()

		log.Printf("authentication key triple generated successfully for %s\n", request.RemoteAddr)

		data := map[string]string{
			"exchange_key": auth.ExchangeKey,
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

		log.Printf("exchange key delivered successfully to %s\n", request.RemoteAddr)
	})

	router.HandleFunc("/auth/authorize/{exchange_key}", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("attempting to authorize exchange key provided by %s...\n", request.RemoteAddr)

		exchangeKey, ok := mux.Vars(request)["exchange_key"]
		if !ok {
			log.Printf("authorization of exchange key provided by %s failed: no exchange key was actually provided\n", request.RemoteAddr)
			return
		}

		log.Println("initiating login request for", request.RemoteAddr)

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

		params := url.Values{
			"username": []string{username},
			"password": []string{password},
			"login":    []string{"Влез"},
		}
		encodedParams := params.Encode()
		encodedParamsReader := strings.NewReader(encodedParams)
		context := colly.NewContext()
		context.Put("exchange_key", exchangeKey)
		context.Put("remote_addr", request.RemoteAddr)
		err := target.Collector.Request(http.MethodPost, config.BaseURL+"/ucp.php?mode=login", encodedParamsReader, context, nil)
		if err != nil {
			log.Printf("login request from %s to target %s failed: could not authenticate to target: failed to initiate POST request: %s\n", request.RemoteAddr, configName, err.Error())
			return
		}

		writer.Write([]byte(fmt.Sprintf("attempting to authorize exchange key %s provided by %s by logging into the target...\n", exchangeKey, request.RemoteAddr)))
	})

	router.HandleFunc("/auth/exchange_key/{exchange_key}", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("trying to fetch the authorization and signing key corresponding to the exchange key provided by %s...\n", request.RemoteAddr)

		exchangeKey, ok := mux.Vars(request)["exchange_key"]
		if !ok {
			log.Printf("authorization of exchange key provided by %s failed: no exchange key was actually provided\n", request.RemoteAddr)
			return
		}

		server.Mutex.RLock()
		auth, ok := server.AuthMap[exchangeKey]
		if !ok {
			log.Printf("retrieval of authorization/signing key pair corresponding to the exchange key provided by %s failed: exchange key not found in keymap\n", request.RemoteAddr)
			return
		}
		if !auth.IsAuthorized {
			log.Printf("retrieval of authorization/signing key pair corresponding to the exchange key provided by %s failed: exchange key was not authorized\n", request.RemoteAddr)
			return
		}
		server.Mutex.RUnlock()

		data := map[string]string{
			"auth_key": auth.AuthKey,
			"sign_key": auth.SignKey,
		}
		response := responseBody{
			Status: 200,
			Data:   data,
		}
		responseText, err := json.Marshal(response)
		if err != nil {
			log.Printf("retrieval of authorization/signing key pair corresponding to the exchange key provided by %s failed: could not serialize response data to JSON: %s\n", request.RemoteAddr, err.Error())
			return
		}

		_, err = writer.Write(responseText)
		if err != nil {
			log.Printf("retrieval of authorization/signing key pair corresponding to the exchange key provided by %s failed: could not send serialized response data: %s\n", request.RemoteAddr, err.Error())
			return
		}

		log.Printf("authorization of exchange key %s complete\n", request.RemoteAddr)
	})

	router.HandleFunc("/auth/verify", func(writer http.ResponseWriter, request *http.Request) {
		var response responseBody

		isAuthenticated, err := authenticate(&server, writer, request)
		if err != nil {
			data := map[string]interface{}{
				"valid": false,
				"error": err.Error(),
			}
			response = responseBody{
				Status: 401,
				Data:   data,
			}
		} else if !isAuthenticated {
			data := map[string]interface{}{
				"valid":    true,
				"usertype": "member",
			}
			response = responseBody{
				Status: 200,
				Data:   data,
			}
		} else {
			data := map[string]interface{}{
				"valid": false,
			}
			response = responseBody{
				Status: 200,
				Data:   data,
			}
		}

		responseText, err := json.Marshal(response)
		if err != nil {
			log.Printf("authentication request from %s failed: could not serialize response data to JSON: %s\n", request.RemoteAddr, err.Error())
			return
		}

		_, err = writer.Write(responseText)
		if err != nil {
			log.Printf("authentication request from %s failed: could not send serialized response data: %s\n", request.RemoteAddr, err.Error())
			return
		}
	})

	http.Handle("/", router)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
