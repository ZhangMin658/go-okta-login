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

// func middleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
// 		if len(authHeader) != 2 {
// 			fmt.Println("Malformed token")
// 			w.WriteHeader(http.StatusUnauthorized)
// 			w.Write([]byte("Malformed Token"))
// 		} else {
// 			jwtToken := authHeader[1]
// 			token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
// 				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
// 				}
// 				return []byte(SECRETKEY), nil
// 			})

// 			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
// 				ctx := context.WithValue(r.Context(), "props", claims)
// 				// Access context values in handlers like this
// 				// props, _ := r.Context().Value("props").(jwt.MapClaims)
// 				next.ServeHTTP(w, r.WithContext(ctx))
// 			} else {
// 				fmt.Println(err)
// 				w.WriteHeader(http.StatusUnauthorized)
// 				w.Write([]byte("Unauthorized"))
// 			}
// 		}
// 	})
// }

func main() {
	oktaUtils.ParseEnvironment()

	// http.HandleFunc("/", HomeHandler)
	// http.HandleFunc("/login", LoginHandler)
	// http.HandleFunc("/authorization-code/callback", AuthCodeCallbackHandler)
	// http.HandleFunc("/profile", ProfileHandler)
	// http.HandleFunc("/logout", LogoutHandler)

	// log.Print("server starting at localhost:8080 ... ")
	// err := http.ListenAndServe(":8080", mux)
	// if err != nil {
	// 	log.Printf("the HTTP server failed to start: %s", err)
	// 	os.Exit(1)
	// }

	// mux := http.NewServeMux()

	// mux.HandleFunc("/", HomeHandler)
	// mux.HandleFunc("/login", LoginHandler)
	// mux.HandleFunc("/authorization-code/callback", AuthCodeCallbackHandler)
	// mux.HandleFunc("/profile", ProfileHandler)
	// mux.HandleFunc("/logout", LogoutHandler)
	// mux.HandleFunc("/json-output", jsonOutput)

	// http.ListenAndServe(":8080", mux)

	http.Handle("/", middleware(HomeHandler))
	http.Handle("/login", middleware(LoginHandler))
	http.Handle("/authorization-code/callback", middleware(AuthCodeCallbackHandler))
	http.Handle("/profile", middleware(ProfileHandler))
	http.Handle("/logout", middleware(LogoutHandler))
	http.Handle("/json-output", middleware(jsonOutput))

	log.Fatal(http.ListenAndServe(":8080", nil))
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
