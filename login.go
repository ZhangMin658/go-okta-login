package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	oktaUtils "github.com/okta/samples-golang/custom-login/utils"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	nonce, _ = oktaUtils.GenerateNonce()
	type customData struct {
		Profile         map[string]string
		IsAuthenticated bool
		BaseUrl         string
		ClientId        string
		Issuer          string
		State           string
		Nonce           string
	}

	issuerParts, _ := url.Parse(os.Getenv("ISSUER"))
	baseUrl := issuerParts.Scheme + "://" + issuerParts.Hostname()
	log.Printf("%s", issuerParts)

	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		BaseUrl:         baseUrl,
		ClientId:        os.Getenv("CLIENT_ID"),
		Issuer:          os.Getenv("ISSUER"),
		State:           state,
		Nonce:           nonce,
	}
	tpl.ExecuteTemplate(w, "login.gohtml", data)
}
