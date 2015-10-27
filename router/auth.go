package router

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/log"
	ms_http "github.com/MSOpenTech/azure-sdk-for-go/core/http"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/*
Sample PureHub response:
{
	"access_token": "a-long-token",
	"token_type": "bearer",
	"expires_in": 3599,
	"userName": "user@example.com",
	".issued": "Thu, 12 Feb 2015 12:15:23 GMT",
	".expires": "Thu, 12 Feb 2015 13:15:23 GMT"
}
*/
type pureHubAuthResponse struct {
	AccessToken string `json:"access_token"`
	Expires     string `json:".expires"`
}

// This is stored in the 'value' part of targetPassThroughAuth.tokenMap
// The key is the user identity
type yellowfinToken struct {
	JSESSIONID string
	IPID       string
}

// Returns true if the request should continue to be passed through the router
// If you return false, then you must already have sent an appropriate error response to 'w'.
func authPassThrough(log *log.Logger, w http.ResponseWriter, req *http.Request, authData *imqsAuthResponse, target *targetPassThroughAuth) bool {
	switch target.config.Type {
	case AuthPassThroughNone:
		return true
	case AuthPassThroughPureHub:
		return authInjectPureHub(log, w, req, target)
	case AuthPassThroughYellowfin:
		return authInjectYellowfin(log, w, req, authData, target)
	default:
		return true
	}
}

func authInjectPureHub(log *log.Logger, w http.ResponseWriter, req *http.Request, target *targetPassThroughAuth) bool {
	// The 'inject' function assumes you have obtained a lock (read or write) on "target.lock"
	inject := func() {
		req.Header.Set("Authorization", "Bearer "+target.token)
	}

	// Run with two attempts.
	// First attempt is optimistic. We take the read lock, and inject the auth header if it is valid.
	// On the second attempt we take the write lock, and generate a new token.

	done := false
	target.lock.RLock()
	if target.token != "" && target.tokenExpires.After(time.Now()) {
		done = true
		inject()
	}
	target.lock.RUnlock()
	if done {
		return true
	}

	// Acquire a new token
	target.lock.Lock()
	err := pureHubGetToken(log, target)
	if err == nil {
		log.Infof("Success acquiring PureHub authentication token")
		inject()
	} else {
		log.Infof("Error acquiring PureHub authentication token: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
	}
	target.lock.Unlock()

	return err != nil
}

func pureHubGetToken(log *log.Logger, target *targetPassThroughAuth) error {
	request_body := "grant_type=password&username=" + url.QueryEscape(target.config.Username) + "&password=" + url.QueryEscape(target.config.Password)
	resp, err := ms_http.Post(target.config.LoginURL, "application/x-www-form-urlencoded", strings.NewReader(request_body))
	if err != nil {
		return fmt.Errorf("http.Post: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		var token pureHubAuthResponse
		if err = json.Unmarshal(body, &token); err == nil {
			target.token = token.AccessToken
			target.tokenExpires, err = time.Parse(time.RFC1123, token.Expires)
			if err == nil {
				// Lower the possibility of using an expired token. We happen to know that they last one hour,
				// so chopping one minute off it should be fine.
				target.tokenExpires = target.tokenExpires.Add(-60 * time.Second)
			}
		} else {
			return fmt.Errorf("Error decoding JSON: %v", err)
		}
	} else {
		return fmt.Errorf("%v: %v", resp.Status, err)
	}
	return err
}

func authInjectYellowfin(log *log.Logger, w http.ResponseWriter, req *http.Request, authData *imqsAuthResponse, target *targetPassThroughAuth) bool {
	if authData == nil {
		log.Errorf("For Yellowfin transparent authentication, you must also enforce authorization")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return false
	}

	inject := func(tok *yellowfinToken) {
		// During initial deployment of this feature, people will still have yellowfin cookies such as JSESSIONID
		// lingering in their browser. We need to make sure that we're clobbering those here. So what we're doing here
		// is discarding the cookies that the user sent from his browser.
		orgCookies := req.Cookies()
		req.Header.Del("Cookie")
		// Add back all other cookies
		for _, c := range orgCookies {
			if c.Name != "JSESSIONID" && c.Name != "IPID" {
				req.AddCookie(c)
			}
		}
		// Inject our yellowfin cookies
		req.AddCookie(&http.Cookie{
			Name:  "JSESSIONID",
			Value: tok.JSESSIONID,
		})
		req.AddCookie(&http.Cookie{
			Name:  "IPID",
			Value: tok.IPID,
		})
	}

	// The acquisition of a new cookie is the somewhat nontrivial case,
	// because we need to ensure that we don't try and log a person in from more than one
	// concurrent thread.
	for start := time.Now(); time.Now().Sub(start).Seconds() < 15; {
		// -- Fetch cached token --
		done := false
		target.lock.RLock()
		token_g := target.tokenMap[authData.Identity]
		if token_g != nil {
			done = true
			inject(token_g.(*yellowfinToken))
		}
		target.lock.RUnlock()
		if done {
			return true
		}

		// -- Acquire new token --

		// Acquire a lock on the USER who is trying to login to yellowfin
		haveUserLock := false
		target.lock.Lock()
		if !target.tokenLock[authData.Identity] {
			target.tokenLock[authData.Identity] = true
			haveUserLock = true
		}
		target.lock.Unlock()

		if haveUserLock {
			token := authYellowfinLogin(log, w, req, authData)
			if token != nil {
				// Insert cached token
				target.lock.Lock()
				target.tokenMap[authData.Identity] = token
				target.tokenLock[authData.Identity] = false
				target.lock.Unlock()
			} else {
				// Give up, because login failed
				target.lock.Lock()
				target.tokenLock[authData.Identity] = false
				target.lock.Unlock()
				return false
			}
		} else {
			// It's likely that by the time we wake up, our user will be logged in.
			log.Infof("Backing off on yellowfin login: %v", authData.Identity)
			time.Sleep(time.Millisecond * 50)
		}
	}

	log.Errorf("High-level timeout while trying to login to yellowfin for: %v", authData.Identity)
	http.Error(w, "Not authorized", http.StatusUnauthorized)

	return false
}

func authYellowfinLogin(log *log.Logger, w http.ResponseWriter, req *http.Request, authData *imqsAuthResponse) *yellowfinToken {
	authReq, err := ms_http.NewRequest("POST", imqsauth_url+"/login_yellowfin", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	headAuth := req.Header.Get("Authorization")
	if headAuth != "" {
		authReq.Header.Set("Authorization", headAuth)
	}
	cookieSession, _ := req.Cookie(imqsauth_cookie)
	if cookieSession != nil {
		authReq.AddCookie(copyCookieToMSHTTP(cookieSession))
	}

	authResp, err := ms_http.DefaultClient.Do(authReq)
	if err != nil {
		log.Errorf("Error logging in to yellowfin: (Transport error: %v)", err)
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return nil
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusOK {
		log.Errorf("Error logging in to yellowfin (HTTP code: %v)", authResp.Status)
		http.Error(w, authResp.Status, authResp.StatusCode)
		return nil
	}

	token := &yellowfinToken{}
	for _, c := range authResp.Cookies() {
		switch c.Name {
		case "JSESSIONID":
			token.JSESSIONID = c.Value
		case "IPID":
			token.IPID = c.Value
		}
	}

	if token.JSESSIONID != "" && token.IPID != "" {
		log.Infof("Transparent login to yellowfin: %v", authData.Identity)
		return token
	}

	log.Errorf("Error logging in to yellowfin. Not enough cookies. (JSESSIONID='%v' IPID='%v')", token.JSESSIONID, token.IPID)
	http.Error(w, "Error loggin in to yellowfin", http.StatusInternalServerError)

	return nil
}
