package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	errors "git.sequentialread.com/forest/pkg-errors"
)

var httpClient *http.Client
var powAPIURL *url.URL
var powChallenges []string

var items []string

// 5 bits of difficulty, 1 in 2^6 (1 in 32) tries will succeed on average.
//
// 7 bits of difficulty would be ok for apps that are never used on mobile phones, 5 is better suited for mobile apps
const powDifficultyLevel = 7

func main() {

	httpClient = &http.Client{
		Timeout: time.Second * time.Duration(5),
	}

	apiToken := os.ExpandEnv("$BOT_DETERRENT_API_TOKEN")
	if apiToken == "" {
		panic(errors.New("can't start the app, the BOT_DETERRENT_API_TOKEN environment variable is required"))
	}

	var err error
	powAPIURL, err = url.Parse("http://localhost:2370")
	if err != nil {
		panic(errors.New("can't start the app because can't parse powAPIURL"))
	}

	err = loadChallenges(apiToken)
	if err != nil {
		panic(errors.Wrap(err, "can't start the app because could not loadChallenges():"))
	}

	_, err = os.ReadFile("index.html")
	if err != nil {
		panic(errors.Wrap(err, "can't start the app because can't open the template file. Are you in the right directory? "))
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("../static/"))))

	http.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {

		// The user submitted a POST request, attempting to add a new item to the list
		if request.Method == "POST" {

			// Ask the bot deterrent server if the user's proof of work result is legit,
			// and if not, return HTTP 400 Bad Request
			err := request.ParseForm()
			if err == nil {
				err = validatePow(apiToken, request.Form.Get("challenge"), request.Form.Get("nonce"))
			}

			if err != nil {
				responseWriter.WriteHeader(400)
				responseWriter.Write([]byte(fmt.Sprintf("400 bad request: %s", err)))
				return
			}

			// Validation passed, add the user's new item to the list
			items = append(items, request.Form.Get("item"))

			http.Redirect(responseWriter, request, "/", http.StatusFound)
			return
		}

		// if it looks like we will run out of challenges soon, then kick off a goroutine to go get more in the background
		// note that in a real application in production, you would want to use a lock or mutex to ensure that
		// this only happens once if lots of requests come in at the same time
		if len(powChallenges) > 0 && len(powChallenges) < 5 {
			go loadChallenges(apiToken)
		}

		// if we somehow completely ran out of challenges, load more synchronously
		if len(powChallenges) == 0 {
			err = loadChallenges(apiToken)
			if err != nil {
				log.Printf("loading bot deterrent challenges failed: %v", err)
				responseWriter.WriteHeader(500)
				responseWriter.Write([]byte("bot deterrent api error"))
				return
			}
		}

		// This gets & consumes the next challenge from the begining of the slice
		challenge := powChallenges[0]
		powChallenges = powChallenges[1:]

		// render the page HTML & output the result to the web browser
		htmlBytes, err := renderPageTemplate(challenge)
		if err != nil {
			log.Printf("renderPageTemplate(): %v", err)
			responseWriter.WriteHeader(500)
			responseWriter.Write([]byte("500 internal server error"))
			return
		}
		responseWriter.Write(htmlBytes)
	})

	log.Println("📋  Todo List example application listening on port 8080")

	err = http.ListenAndServe(":8080", nil)

	// if got this far it means server crashed!
	panic(err)
}

func renderPageTemplate(challenge string) ([]byte, error) {

	// in a real application in production you would read the template file & parse it 1 time when the app starts
	// I'm doing it for each request here just to make it easier to hack on it while its running 😇
	indexHTMLTemplateString, err := ioutil.ReadFile("index.html")
	if err != nil {
		return nil, errors.Wrap(err, "can't open the template file. Are you in the right directory? ")
	}
	pageTemplate, err := template.New("master").Parse(string(indexHTMLTemplateString))
	if err != nil {
		return nil, errors.Wrap(err, "can't parse the template file: ")
	}

	// constructing an instance of an anonymous struct type to contain all the data
	// that we need to pass to the template
	pageData := struct {
		Challenge                  string
		Items                      []string
		CrossOriginStaticAssetsUrl string
	}{
		Challenge:                  challenge,
		Items:                      items,
		CrossOriginStaticAssetsUrl: fmt.Sprintf("%s/pow-bot-deterrent-static", powAPIURL.String()),
	}
	var outputBuffer bytes.Buffer
	err = pageTemplate.Execute(&outputBuffer, pageData)
	if err != nil {
		return nil, errors.Wrap(err, "rendering page template failed: ")
	}

	return outputBuffer.Bytes(), nil
}

func loadChallenges(apiToken string) error {

	query := url.Values{}
	query.Add("difficultyLevel", strconv.Itoa(powDifficultyLevel))

	loadURL := url.URL{
		Scheme:   powAPIURL.Scheme,
		Host:     powAPIURL.Host,
		Path:     filepath.Join(powAPIURL.Path, "GetChallenges"),
		RawQuery: query.Encode(),
	}

	request, err := http.NewRequest("POST", loadURL.String(), nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	if err != nil {
		return err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}

	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		return fmt.Errorf(
			"load proof of work bot deterrent challenges api returned http %d: %s",
			response.StatusCode, string(responseBytes),
		)
	}

	err = json.Unmarshal(responseBytes, &powChallenges)
	if err != nil {
		return err
	}

	if len(powChallenges) == 0 {
		return errors.New("proof of work bot deterrent challenges api returned empty array")
	}

	return nil
}

func validatePow(apiToken, challenge, nonce string) error {
	query := url.Values{}
	query.Add("challenge", challenge)
	query.Add("nonce", nonce)

	verifyURL := url.URL{
		Scheme:   powAPIURL.Scheme,
		Host:     powAPIURL.Host,
		Path:     filepath.Join(powAPIURL.Path, "Verify"),
		RawQuery: query.Encode(),
	}

	request, err := http.NewRequest("POST", verifyURL.String(), nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	if err != nil {
		return err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		bodyString := "http read error"
		bytez, err := io.ReadAll(response.Body)
		if err == nil {
			bodyString = string(bytez)
		}
		log.Printf("validation failed: HTTP %d: %s\n", response.StatusCode, bodyString)
		return errors.New("PoW bot deterrent validation failed")
	}
	return nil
}
