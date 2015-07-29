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

/* Sample PureHub response:
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

// Returns true if the request should continue to be passed through the router
func authPassThrough(log *log.Logger, w http.ResponseWriter, req *http.Request, target *targetPassThroughAuth) bool {
	switch target.config.Type {
	case AuthPassThroughNone:
		return true
	case AuthPassThroughPureHub:
		return authInjectPureHub(log, w, req, target)
	default:
		return true
	}
}

func authInjectPureHub(log *log.Logger, w http.ResponseWriter, req *http.Request, target *targetPassThroughAuth) bool {
	// The 'inject' function assumes you have obtained the lock on target.token
	inject := func() {
		req.Header.Set("Authorization", "Bearer "+target.token)
	}

	// Run with two attempts.
	// First attempt is optimistic. We take the read lock, and inject the auth header if it is valid.
	// On the second attempt we take the write lock, and generate a new token.
	for try := 0; try < 2; try++ {
		if try == 0 {
			target.lock.RLock()
		} else {
			target.lock.Lock()
		}

		if target.token != "" && target.tokenExpires.After(time.Now()) {
			inject()
		} else if try == 1 {
			// Acquire a new token
			err := pureHubGetToken(log, target)
			if err != nil {
				log.Infof("Error acquiring PureHub authentication token: %v", err)
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return false
			}
			log.Infof("Success acquiring PureHub authentication token")
			inject()
		}

		if try == 0 {
			target.lock.RUnlock()
		} else {
			target.lock.Unlock()
		}
	}
	return true
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
