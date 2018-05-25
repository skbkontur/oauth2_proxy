package providers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/dgrijalva/jwt-go"
	yaml "gopkg.in/yaml.v2"
)

type authConfiguration map[string][]string

// PassportProvider of auth
type PassportProvider struct {
	*ProviderData
	userGroups sync.Map
	auth       authConfiguration
}

// NewPassportProvider creates passport provider
func NewPassportProvider(p *ProviderData) *PassportProvider {
	p.ProviderName = "Passport"
	return &PassportProvider{ProviderData: p}
}

func (p *PassportProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	token := []byte(fmt.Sprintf("%s:%s", p.ClientID, p.ClientSecret))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(token)))

	resp, err := p.apiRequest(req)
	if err != nil {
		return nil, err
	}
	accessToken, err := resp.Get("access_token").String()
	s = &SessionState{
		AccessToken: accessToken,
	}

	return
}

func (p *PassportProvider) GetEmailAddress(s *SessionState) (string, error) {
	email := ""
	token, err := jwt.Parse(s.AccessToken, func(token *jwt.Token) (interface{}, error) {
		passportKey := os.Getenv("PASSPORT_KEY")
		publicKey, err := ioutil.ReadFile(passportKey)
		if err != nil {
			log.Printf("Error loading public key: %s", err.Error())
		}
		return publicKey, nil
	})
	if err == nil && token.Valid {
		login := strings.ToLower(token.Claims["sub"].(string))
		loginParts := strings.Split(login, "\\")
		if len(loginParts) > 1 {
			email = fmt.Sprintf("%s@%s", loginParts[1], loginParts[0])
			groups, err := p.getUserGroups(token.Raw)
			if err != nil {
				log.Printf("Failed to get %s groups: %s", email, err.Error())
			}
			p.userGroups.Store(email, groups)
		} else {
			email = fmt.Sprintf("%s@local", loginParts[0])
			p.userGroups.Store(email, []string{"local"})
		}
	}
	return email, err
}

func (p *PassportProvider) apiRequest(req *http.Request) (*simplejson.Json, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return nil, err
	}
	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, err
	}
	return data, nil

}

func (p *PassportProvider) getUserGroups(token string) ([]string, error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	req, err := http.NewRequest("GET", p.ProfileURL.String(), bytes.NewBufferString(params.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	if err != nil {
		log.Printf("failed building request %s", err.Error())
		return nil, err
	}
	json, err := p.apiRequest(req)
	if err != nil {
		log.Printf("failed making request %s", err.Error())
		return nil, err
	}

	groupJson := json.Get("group")
	groups, err := groupJson.String()
	if err == nil {
		return strings.Split(groups, ","), nil
	}
	return groupJson.StringArray()
}

// ValidateRequest validates that the request fits configured provider
// authorization groups
func (p *PassportProvider) ValidateRequest(req *http.Request, s *SessionState) (bool, error) {
	if s == nil {
		return false, errors.New("Session not established")
	}
	uri := strings.Split(req.Host, ":")[0] + req.URL.Path
	allowedGroups := p.getAllowedGroups(uri)
	_, exAll := allowedGroups["*"]
	if exAll {
		return true, nil
	}
	groups, isKnownUser := p.userGroups.Load(s.Email)
	if !isKnownUser {
		return false, errors.New("Session need to be re-established")
	}
	for _, group := range groups.([]string) {
		val, ex := allowedGroups[group]
		if ex && val {
			return true, nil
		}
	}

	return false, nil
}

// GetLoginURL with typical oauth parameters
func (p *PassportProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

func (p *PassportProvider) LoadAllowed() {
	auth := os.Getenv("AUTH_FILE")
	yamlFile, err := ioutil.ReadFile(auth)
	if err != nil {
		log.Printf("yamlFile.Get err %v, %s ", err, auth)
		return
	}
	err = yaml.Unmarshal(yamlFile, &p.auth)
	if err != nil {
		log.Fatalf("yaml.Unmarshal err %v", err)
		return
	}
}

func (p *PassportProvider) getAllowedGroups(uri string) map[string]bool {
	bestMatch := ""
	for key := range p.auth {
		if strings.HasPrefix(uri, key) {
			if len(bestMatch) < len(key) {
				bestMatch = key
			}
		}
	}
	groups, ex := p.auth[bestMatch]
	res := make(map[string]bool)
	if ex {
		for _, group := range groups {
			res[group] = true
		}
	}
	return res
}
