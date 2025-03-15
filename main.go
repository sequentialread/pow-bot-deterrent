package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	configlite "git.sequentialread.com/forest/config-lite"
	errors "git.sequentialread.com/forest/pkg-errors"
	"golang.org/x/crypto/scrypt"
)

type Config struct {
	ListenPort             int    `json:"listen_port"`
	BatchSize              int    `json:"batch_size"`
	DeprecateAfterBatches  int    `json:"deprecate_after_batches"`
	ScryptCPUAndMemoryCost int    `json:"scrypt_cpu_and_memory_cost"`
	AdminAPIToken          string `json:"admin_api_token"`

	EmailAddress string `json:"email_address"`
	// port 993 (IMAPS)
	// port 143 (STARTTLS) [deprecated!]
	ImapHost       string `json:"imap_host"`
	ImapPort       int    `json:"imap_port"`
	ImapEncryption string `json:"imap_encryption"`
	ImapUsername   string `json:"imap_username"`
	ImapPassword   string `json:"imap_password"`
}

// https://en.wikipedia.org/wiki/Scrypt
type ScryptParameters struct {
	CPUAndMemoryCost int `json:"N"`
	BlockSize        int `json:"r"`
	Paralellization  int `json:"p"`
	KeyLength        int `json:"klen"`
}

type Challenge struct {
	ScryptParameters
	Preimage        string `json:"i"`
	Difficulty      string `json:"d"`
	DifficultyLevel int    `json:"dl"`
}

var config Config
var appDirectory string
var scryptParameters ScryptParameters
var currentChallengesGeneration = map[string]int{}
var challenges = map[string]map[string]int{}

func main() {

	var err error

	apiTokensFolder := readConfiguration()

	requireMethod := func(method string) func(http.ResponseWriter, *http.Request) bool {
		return func(responseWriter http.ResponseWriter, request *http.Request) bool {
			if request.Method != method {
				responseWriter.Header().Set("Allow", method)
				http.Error(responseWriter, fmt.Sprintf("405 Method Not Allowed, try %s", method), http.StatusMethodNotAllowed)
				return true
			}
			return false
		}
	}

	requireAdmin := func(responseWriter http.ResponseWriter, request *http.Request) bool {
		if request.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", config.AdminAPIToken) {
			http.Error(responseWriter, "401 Unauthorized", http.StatusUnauthorized)
			return true
		}
		return false
	}

	requireToken := func(responseWriter http.ResponseWriter, request *http.Request) bool {
		authorizationHeader := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorizationHeader, "Bearer ") {
			http.Error(responseWriter, "401 Unauthorized: Authorization header is required and must start with 'Bearer '", http.StatusUnauthorized)
			return true
		}
		token := strings.TrimPrefix(authorizationHeader, "Bearer ")
		if token == "" {
			http.Error(responseWriter, "401 Unauthorized: Authorization Bearer token is required", http.StatusUnauthorized)
			return true
		}
		if !regexp.MustCompile("^[0-9a-f]{32}$").MatchString(token) {
			errorMsg := fmt.Sprintf("401 Unauthorized: Authorization Bearer token '%s' must be a 32 character hex string", token)
			http.Error(responseWriter, errorMsg, http.StatusUnauthorized)
			return true
		}
		fileInfos, err := ioutil.ReadDir(apiTokensFolder)
		if err != nil {
			log.Printf("failed to list the apiTokensFolder (%s): %v", apiTokensFolder, err)
			http.Error(responseWriter, "500 internal server error", http.StatusInternalServerError)
			return true
		}
		foundToken := false
		for _, fileInfo := range fileInfos {
			if strings.HasPrefix(fileInfo.Name(), token) {
				foundToken = true
				break
			}
		}
		if !foundToken {
			errorMsg := fmt.Sprintf("401 Unauthorized: Authorization Bearer token '%s' was in the right format, but it was unrecognized", token)
			http.Error(responseWriter, errorMsg, http.StatusUnauthorized)
			return true
		}
		return false
	}

	myHTTPHandleFunc("/Tokens", requireMethod("GET"), requireAdmin, func(responseWriter http.ResponseWriter, request *http.Request) bool {
		fileInfos, err := ioutil.ReadDir(apiTokensFolder)
		if err != nil {
			log.Printf("failed to list the apiTokensFolder (%s): %v", apiTokensFolder, err)
			http.Error(responseWriter, "500 internal server error", http.StatusInternalServerError)
			return true
		}

		output := []string{}

		for _, fileInfo := range fileInfos {
			filenameSplit := strings.Split(fileInfo.Name(), "_")
			if len(filenameSplit) == 2 {
				filepath := path.Join(apiTokensFolder, fileInfo.Name())
				content, err := ioutil.ReadFile(filepath)
				if err != nil {
					log.Printf("failed to read the token file (%s): %v", filepath, err)
					http.Error(responseWriter, "500 internal server error", http.StatusInternalServerError)
					return true
				}
				contentInt64, err := strconv.ParseInt(string(content), 10, 64)
				timestampString := time.Unix(contentInt64, 0).UTC().Format(time.RFC3339)
				output = append(output, fmt.Sprintf("%s,%s,%d,%s", filenameSplit[0], filenameSplit[1], contentInt64, timestampString))
			}

		}

		responseWriter.Header().Set("Content-Type", "text/plain")
		responseWriter.Write([]byte(strings.Join(output, "\n")))

		return true
	})

	myHTTPHandleFunc("/Tokens/Create", requireMethod("POST"), requireAdmin, func(responseWriter http.ResponseWriter, request *http.Request) bool {
		name := request.URL.Query().Get("name")
		if name == "" {
			http.Error(responseWriter, "400 Bad Request: url param ?name=<string> is required", http.StatusBadRequest)
			return true
		}
		// we use underscore as a syntax character in the filename, so we have to remove it from the user-inputted name
		name = strings.ReplaceAll(name, "_", "-")
		// let's also remove any sort of funky or path-related characters
		name = strings.ReplaceAll(name, "*", "")
		name = strings.ReplaceAll(name, "?", "")
		name = strings.ReplaceAll(name, "/", "-")
		name = strings.ReplaceAll(name, "\\", "-")
		name = strings.ReplaceAll(name, ".", "-")

		tokenBytes := make([]byte, 16)
		rand.Read(tokenBytes)

		ioutil.WriteFile(
			path.Join(apiTokensFolder, fmt.Sprintf("%x_%s", tokenBytes, name)),
			[]byte(fmt.Sprintf("%d", time.Now().Unix())),
			0644,
		)

		fmt.Fprintf(responseWriter, "%x", tokenBytes)

		return true
	})

	myHTTPHandleFunc("/Tokens/Revoke", requireMethod("POST"), requireAdmin, func(responseWriter http.ResponseWriter, request *http.Request) bool {
		token := request.URL.Query().Get("token")
		if token == "" {
			http.Error(responseWriter, "400 Bad Request: url param ?token=<string> is required", http.StatusBadRequest)
			return true
		}
		if !regexp.MustCompile("^[0-9a-f]{32}$").MatchString(token) {
			errorMsg := fmt.Sprintf("400 Bad Request: url param ?token=%s must be a 32 character hex string", token)
			http.Error(responseWriter, errorMsg, http.StatusBadRequest)
			return true
		}

		fileInfos, err := ioutil.ReadDir(apiTokensFolder)
		if err != nil {
			log.Printf("failed to list the apiTokensFolder (%s): %v", apiTokensFolder, err)
			http.Error(responseWriter, "500 internal server error", http.StatusInternalServerError)
			return true
		}
		for _, fileInfo := range fileInfos {
			if strings.HasPrefix(fileInfo.Name(), token) {
				os.Remove(path.Join(apiTokensFolder, fileInfo.Name()))
			}
		}

		responseWriter.Write([]byte("Revoked"))
		return true
	})

	myHTTPHandleFunc("/GetChallenges", requireMethod("POST"), requireToken, func(responseWriter http.ResponseWriter, request *http.Request) bool {

		// requireToken already validated the API Token, so we can just do this:
		token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")

		if _, has := currentChallengesGeneration[token]; !has {
			currentChallengesGeneration[token] = 0
		}
		if _, has := challenges[token]; !has {
			challenges[token] = map[string]int{}
		}
		currentChallengesGeneration[token]++

		requestQuery := request.URL.Query()
		difficultyLevelString := requestQuery.Get("difficultyLevel")
		difficultyLevel, err := strconv.Atoi(difficultyLevelString)
		if err != nil {
			errorMessage := fmt.Sprintf(
				"400 url param ?difficultyLevel=%s value could not be converted to an integer",
				difficultyLevelString,
			)
			http.Error(responseWriter, errorMessage, http.StatusBadRequest)
			return true
		}

		toReturn := make([]string, config.BatchSize)
		for i := 0; i < config.BatchSize; i++ {
			preimageBytes := make([]byte, 8)
			_, err := rand.Read(preimageBytes)
			if err != nil {
				log.Printf("read random bytes failed: %v", err)
				http.Error(responseWriter, "500 internal server error", http.StatusInternalServerError)
				return true
			}
			preimage := base64.StdEncoding.EncodeToString(preimageBytes)
			difficultyBytes := make([]byte, int(math.Ceil(float64(difficultyLevel)/float64(8))))

			for j := 0; j < len(difficultyBytes); j++ {
				difficultyByte := byte(0)
				for k := 0; k < 8; k++ {
					currentBitIndex := (j*8 + (7 - k))
					if currentBitIndex+1 > difficultyLevel {
						difficultyByte = difficultyByte | 1<<k
					}
				}
				difficultyBytes[j] = difficultyByte
			}

			difficulty := hex.EncodeToString(difficultyBytes)
			challenge := Challenge{
				Preimage:        preimage,
				Difficulty:      difficulty,
				DifficultyLevel: difficultyLevel,
			}
			challenge.CPUAndMemoryCost = scryptParameters.CPUAndMemoryCost
			challenge.BlockSize = scryptParameters.BlockSize
			challenge.Paralellization = scryptParameters.Paralellization
			challenge.KeyLength = scryptParameters.KeyLength

			challengeBytes, err := json.Marshal(challenge)
			if err != nil {
				log.Printf("serialize challenge as json failed: %v", err)
				http.Error(responseWriter, "500 internal server error", http.StatusInternalServerError)
				return true
			}

			challengeBase64 := base64.StdEncoding.EncodeToString(challengeBytes)
			challenges[token][challengeBase64] = currentChallengesGeneration[token]
			toReturn[i] = challengeBase64
		}
		toRemove := []string{}
		for k, generation := range challenges[token] {
			if generation+config.DeprecateAfterBatches < currentChallengesGeneration[token] {
				toRemove = append(toRemove, k)
			}
		}
		for _, k := range toRemove {
			delete(challenges[token], k)
		}

		responseBytes, err := json.Marshal(toReturn)
		if err != nil {
			log.Printf("json marshal failed: %v", err)
			http.Error(responseWriter, "500 internal server error", http.StatusInternalServerError)
			return true
		}

		responseWriter.Write(responseBytes)

		return true
	})

	myHTTPHandleFunc("/Verify", requireMethod("POST"), requireToken, func(responseWriter http.ResponseWriter, request *http.Request) bool {

		// requireToken already validated the API Token, so we can just do this:
		token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")

		requestQuery := request.URL.Query()
		challengeBase64 := requestQuery.Get("challenge")
		nonceHex := requestQuery.Get("nonce")

		_, hasAnyChallenges := challenges[token]
		hasChallenge := false
		if hasAnyChallenges {
			_, hasChallenge = challenges[token][challengeBase64]
		}

		if !hasChallenge {
			errorMessage := fmt.Sprintf("404 challenge given by url param ?challenge=%s was not found", challengeBase64)
			http.Error(responseWriter, errorMessage, http.StatusNotFound)
			return true
		}

		delete(challenges[token], challengeBase64)

		nonceBuffer := make([]byte, 8)
		bytesWritten, err := hex.Decode(nonceBuffer, []byte(nonceHex))
		if nonceHex == "" || err != nil {
			errorMessage := fmt.Sprintf("400 bad request: nonce given by url param ?nonce=%s could not be hex decoded", nonceHex)
			http.Error(responseWriter, errorMessage, http.StatusBadRequest)
			return true
		}

		nonceBytes := nonceBuffer[:bytesWritten]

		challengeJSON, err := base64.StdEncoding.DecodeString(challengeBase64)
		if err != nil {
			log.Printf("challenge %s couldn't be parsed: %v\n", challengeBase64, err)
			http.Error(responseWriter, "500 challenge couldn't be decoded", http.StatusInternalServerError)
			return true
		}
		var challenge Challenge
		err = json.Unmarshal([]byte(challengeJSON), &challenge)
		if err != nil {
			log.Printf("challenge %s (%s) couldn't be parsed: %v\n", string(challengeJSON), challengeBase64, err)
			http.Error(responseWriter, "500 challenge couldn't be parsed", http.StatusInternalServerError)
			return true
		}

		preimageBytes := make([]byte, 8)
		n, err := base64.StdEncoding.Decode(preimageBytes, []byte(challenge.Preimage))
		if n != 8 || err != nil {
			log.Printf("invalid preimage %s: %v\n", challenge.Preimage, err)
			http.Error(responseWriter, "500 invalid preimage", http.StatusInternalServerError)
			return true
		}

		hash, err := scrypt.Key(
			nonceBytes,
			preimageBytes,
			challenge.CPUAndMemoryCost,
			challenge.BlockSize,
			challenge.Paralellization,
			challenge.KeyLength,
		)

		if err != nil {
			log.Printf("scrypt returned error: %v\n", err)
			http.Error(responseWriter, "500 scrypt returned error", http.StatusInternalServerError)
			return true
		}

		hashHex := hex.EncodeToString(hash)
		endOfHash := hashHex[len(hashHex)-len(challenge.Difficulty):]

		log.Printf("endOfHash: %s <= Difficulty: %s", endOfHash, challenge.Difficulty)
		if endOfHash > challenge.Difficulty {
			errorMessage := fmt.Sprintf(
				"400 bad request: nonce given by url param ?nonce=%s did not result in a hash that meets the required difficulty",
				nonceHex,
			)
			http.Error(responseWriter, errorMessage, http.StatusBadRequest)
			return true
		}

		responseWriter.WriteHeader(200)
		responseWriter.Write([]byte("OK"))
		return true
	})

	http.HandleFunc("/static/captcha.css", func(responseWriter http.ResponseWriter, request *http.Request) {
		bytez, _ := os.ReadFile("./static/pow-bot-deterrent.css")
		responseWriter.Header().Set("Content-Type", "text/css")
		responseWriter.Write(bytez)
	})
	http.HandleFunc("/static/captcha.js", func(responseWriter http.ResponseWriter, request *http.Request) {
		bytez, _ := os.ReadFile("./static/pow-bot-deterrent.js")
		responseWriter.Header().Set("Content-Type", "application/javascript")
		responseWriter.Write(bytez)
	})

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	http.Handle("/pow-bot-deterrent-static/", http.StripPrefix("/pow-bot-deterrent-static/", http.FileServer(http.Dir("./static/"))))

	log.Printf("💥  PoW! Bot Deterrent server listening on port %d", config.ListenPort)

	err = http.ListenAndServe(fmt.Sprintf(":%d", config.ListenPort), nil)

	// if got this far it means server crashed!
	panic(err)
}

func myHTTPHandleFunc(path string, stack ...func(http.ResponseWriter, *http.Request) bool) {
	http.HandleFunc(path, func(responseWriter http.ResponseWriter, request *http.Request) {
		for _, handler := range stack {
			if handler(responseWriter, request) {
				break
			}
		}
	})
}

func locateAPITokensFolder() string {
	workingDirectory, err := os.Getwd()
	if err != nil {
		log.Fatalf("locateAPITokensFolder(): can't os.Getwd(): %v", err)
	}
	executableDirectory, err := getCurrentExecDir()
	if err != nil {
		log.Fatalf("locateAPITokensFolder(): can't getCurrentExecDir(): %v", err)
	}

	nextToExecutable := filepath.Join(executableDirectory, "PoW_Bot_Deterrent_API_Tokens")
	inWorkingDirectory := filepath.Join(workingDirectory, "PoW_Bot_Deterrent_API_Tokens")

	nextToExecutableStat, err := os.Stat(nextToExecutable)
	foundKeysNextToExecutable := err == nil && nextToExecutableStat.IsDir()
	inWorkingDirectoryStat, err := os.Stat(inWorkingDirectory)
	foundKeysInWorkingDirectory := err == nil && inWorkingDirectoryStat.IsDir()
	if foundKeysNextToExecutable && foundKeysInWorkingDirectory && workingDirectory != executableDirectory {
		log.Fatalf(`locateAPITokensFolder(): Something went wrong with your installation, 
			I found two PoW_Bot_Deterrent_API_Tokens folders and I'm not sure which one to use.
			One of them is located at %s
			and the other is at %s`, inWorkingDirectory, nextToExecutable)
	}
	if foundKeysInWorkingDirectory {
		return inWorkingDirectory
	} else if foundKeysNextToExecutable {
		return nextToExecutable
	}

	log.Fatalf(`locateAPITokensFolder(): I didn't find a PoW_Bot_Deterrent_API_Tokens folder 
		in the current working directory (in %s) or next to the executable (in %s)`, workingDirectory, executableDirectory)

	return ""
}

func getCurrentExecDir() (dir string, err error) {
	path, err := exec.LookPath(os.Args[0])
	if err != nil {
		fmt.Printf("exec.LookPath(%s) returned %s\n", os.Args[0], err)
		return "", err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Printf("filepath.Abs(%s) returned %s\n", path, err)
		return "", err
	}

	dir = filepath.Dir(absPath)

	return dir, nil
}

func readConfiguration() string {
	apiTokensFolderPath := locateAPITokensFolder()
	appDirectory = filepath.Dir(apiTokensFolderPath)
	configJsonPath := filepath.Join(appDirectory, "config.json")
	err := configlite.ReadConfiguration(configJsonPath, "POW_BOT_DETERRENT", []string{}, reflect.ValueOf(&config))
	if err != nil {
		panic(errors.Wrap(err, "ReadConfiguration returned"))
	}

	errors := []string{}
	if config.ListenPort == 0 {
		config.ListenPort = 2370
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.DeprecateAfterBatches == 0 {
		config.DeprecateAfterBatches = 10
	}
	if config.ScryptCPUAndMemoryCost == 0 {
		config.ScryptCPUAndMemoryCost = 16384
	}
	if config.AdminAPIToken == "" {
		errors = append(errors, "the POW_BOT_DETERRENT_ADMIN_API_TOKEN environment variable is required")
	}

	if config.EmailAddress != "" {
		if config.ImapHost == "" {
			config.ImapHost = "localhost"
		}
		if config.ImapPort == 0 {
			config.ImapPort = 993
		}
		if config.ImapEncryption == "" {
			config.ImapEncryption = "SMTPS"
		}
		if config.ImapEncryption != "STARTTLS" && config.ImapEncryption != "IMAPS" && config.ImapEncryption != "NONE" {
			errors = append(errors, fmt.Sprintf("ImapEncryption '%s' must be IMAPS, STARTTLS or NONE", config.ImapEncryption))
		}
		if config.ImapUsername == "" {
			errors = append(errors, "ImapUsername is required")
		}
		if config.ImapPassword == "" {
			errors = append(errors, "ImapPassword is required")
		}
	}

	if len(errors) > 0 {
		log.Fatalln("💥 PoW Bot Deterrent can't start because there are configuration issues:")
		log.Fatalln(strings.Join(errors, "\n"))
	}

	scryptParameters = ScryptParameters{
		CPUAndMemoryCost: config.ScryptCPUAndMemoryCost,
		BlockSize:        8,
		Paralellization:  1,
		KeyLength:        16,
	}

	log.Println("💥 PoW Bot Deterrent starting up with config:")
	configToLogBytes, _ := json.MarshalIndent(config, "", "  ")
	configToLogString := regexp.MustCompile(
		`("admin_api_token": ")[^"]+(",)`,
	).ReplaceAllString(
		string(configToLogBytes),
		"$1******$2",
	)
	configToLogString = regexp.MustCompile(
		`("imap_password": ")[^"]+(",?)`,
	).ReplaceAllString(
		configToLogString,
		"$1******$2",
	)
	log.Println(configToLogString)

	return apiTokensFolderPath
}
