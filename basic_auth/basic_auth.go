package basic_auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"

	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/jtblin/go-ldap-client"
	//pep_jwt "local.com/leobrada/ztsfc_http_pep/jwt"
)

func Basic_auth(w http.ResponseWriter, req *http.Request) bool {

	//    if perform_x509_auth(w, req) {
	//        //fmt.Printf("User presented Client certificate\n")
	//        fmt.Printf("%s\n", req.TLS.PeerCertificates[0].Subject.String())
	//    }

	return perform_passwd_auth(w, req)
}

// func perform_x509_auth(w http.ResponseWriter, req *http.Request) bool {
// 	// Check if a verified client certificate is present
// 	if len(req.TLS.VerifiedChains) > 0 {
// 		return true
// 	}
// 	return false
// }

func perform_passwd_auth(w http.ResponseWriter, req *http.Request) bool {
	var username, password string

	// TODO: Check for JW Token initially
	// Check if it is a POST request
	if req.Method == "POST" {

		if err := req.ParseForm(); err != nil {
			handleFormReponse("Parsing Error", w)
			return false
		}

		nmbr_of_postvalues := len(req.PostForm)
		if nmbr_of_postvalues != 2 {
			handleFormReponse("Wrong number of POST form values", w)
			return false
		}

		usernamel, exist := req.PostForm["username"]
		username = usernamel[0]
		if !exist {
			handleFormReponse("Username not present or wrong", w)
			return false
		}

		passwordl, exist := req.PostForm["password"]
		password = passwordl[0]
		if !exist {
			handleFormReponse("Password not present or wrong", w)
			return false
		}

		if !userIsInLDAP(username, password) {
			handleFormReponse("Authentication failed for user", w)
			return false
		}

		// Create JWT
		mySigningKey := parseRsaPrivateKeyFromPemStr("./basic_auth/jwt_test_priv.pem")
		ss := createJWToken(mySigningKey, username)
		fmt.Println(ss)

		ztsfc_cookie := http.Cookie{
			Name:   "ztsfc_session",
			Value:  ss,
			MaxAge: 1800,
			Path:   "/",
		}
		http.SetCookie(w, &ztsfc_cookie)

		// TODO: make it user configurable
		// TODO: is there a better solution for the content-length  /body length "bug"?
		req.ContentLength = 0
		http.Redirect(w, req, "https://service1.testbed.informatik.uni-ulm.de"+req.URL.String(), http.StatusSeeOther)
		return true

	} else {
		handleFormReponse("only post methods are accepted in this state", w)
		return false
	}
}

func handleFormReponse(msg string, w http.ResponseWriter) {
	form := `<html>
        <body>
        <center>
        <form action="/" method="post">
        <label for="fname">Username:</label>
        <input type="text" id="username" name="username"><br><br>
        <label for="lname">Password:</label>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Submit">
        </form>
        </center>
        </body>
        </html>
        `

	fmt.Println(msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, form)
}

func createJWToken(mySigningKey *rsa.PrivateKey, username string) string {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		Issuer:    "ztsfc_bauth",
		Subject:   username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, _ := token.SignedString(mySigningKey)

	//    fmt.Printf("%v\n", ss)
	return ss
}

func parseRsaPrivateKeyFromPemStr(privPEMlocation string) *rsa.PrivateKey {
	priv_read_in, err := ioutil.ReadFile(privPEMlocation)
	if err != nil {
		fmt.Printf("Could not read from file.\n")
		return nil
	}

	block, _ := pem.Decode(priv_read_in)
	if block == nil {
		fmt.Printf("Could not decode the read in block.\n")
		return nil
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Could not Parse priv key: %s\n", err.Error())
		return nil
	}

	return priv.(*rsa.PrivateKey)
}

func userIsInLDAP(userName, password string) bool {
	client := &ldap.LDAPClient{
		Base:         "ou=people,dc=planetexpress,dc=com",
		Host:         "10.4.0.52",
		Port:         389,
		UseSSL:       false,
		BindDN:       "cn=admin,dc=planetexpress,dc=com",
		BindPassword: "GoodNewsEveryone",
		UserFilter:   "(uid=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes:   []string{"givenName", "sn", "mail", "uid"},
	}
	// It is the responsibility of the caller to close the connection
	defer client.Close()

	ok, _, err := client.Authenticate(userName, password)
	if err != nil {
		fmt.Printf("Error authenticating user %s: %+v\n", userName, err)
		return false
	}
	if !ok {
		fmt.Printf("Authenticating failed for user %s\n", userName)
		return false
	}
	return true
}
