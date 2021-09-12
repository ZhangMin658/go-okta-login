package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/custom-login/utils"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-custom-login-session-store"))
	state        = generateState()
	nonce        = "NonceNotSetYet"
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func generateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionStore.Get(r, "okta-custom-login-session-store")

		if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
			// Write an error and stop the handler chain
			// http.Error(w, "Forbidden", http.StatusForbidden)
			// http.HandleFunc("/login", LoginHandler)
			r.RequestURI = "/"
			next.ServeHTTP(w, r)
		} else {
			// Do stuff here
			log.Println(r.RequestURI)
			// Call the next handler, which can be another middleware in the chain, or the final handler.
			next.ServeHTTP(w, r)
		}
	})
}

func main() {
	oktaUtils.ParseEnvironment()

	r := mux.NewRouter()

	r.Use(loggingMiddleware)

	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/authorization-code/callback", AuthCodeCallbackHandler)
	r.HandleFunc("/profile", ProfileHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/json", JsonHandler)

	http.ListenAndServe(":8080", r)
}

func exchangeCode(code string, r *http.Request) Exchange {
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-custom-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-custom-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}
