package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/IMQS/log"
	"github.com/IMQS/serviceauth"
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

// Parameters to set when logging into YF
type yellowfinLoginParameters struct {
	ModuleFilter   string
	ScenarioFilter string
}

// This is stored in the 'value' part of targetPassThroughAuth.tokenMap
// The key is the user identity
type yellowfinToken struct {
	UserSession string
	Expires     time.Time
	JSESSIONID  string
	IPID        string
	Parameters  yellowfinLoginParameters
}

// We configure Yellowfin so that internally, it's sessions expire after 31 days.
// However, if the Yellowfin service gets restarted, then Yellowfin discards it's sessions.
// We're probably OK for now, because in regular production, Yellowfin will not get
// restarted on it's own. All services get restarted whenever an update is performed.
// Initially I tried making this timeout short, but that has the downside that the
// existing yellowfin iframe sessions get screwed around. I don't know what causes this,
// but my guess is that it's due to session information encoded in the URL of requests.
// So, the conservative thing to do is to make the timeouts as long as possible. If the
// user goes back to the IMQS home screen, and then from there renavigates to a report,
// then the relogin works as intended. But if he clicks around within the Yellowfin iframe,
// and the session token expires during those clicks, then we start to see broken
// behaviour from yellowfin.
const yellowfinTokenLifetime = 30 * 24 * time.Hour

// Returns true if the request should continue to be passed through the router
// If you return false, then you must already have sent an appropriate error response to 'w'.
func authPassThrough(log *log.Logger, w http.ResponseWriter, req *http.Request, authData *serviceauth.ImqsAuthResponse, target *targetPassThroughAuth) bool {
	switch target.config.Type {
	case AuthPassThroughNone:
		return true
	case AuthPassThroughPureHub:
		return authInjectPureHub(log, w, req, target)
	case AuthPassThroughYellowfin:
		return authInjectYellowfin(log, w, req, authData, target)
	case AuthPassThroughSitePro:
		return authInjectSitePro(log, w, req, target)
	default:
		return true
	}
}

func authInjectSitePro(log *log.Logger, w http.ResponseWriter, req *http.Request, target *targetPassThroughAuth) bool {
	req.SetBasicAuth(target.config.Username, target.config.Password)
	return true
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

func injectYellowfinCookies(req *http.Request, tok *yellowfinToken) {
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

func authInjectYellowfin(log *log.Logger, w http.ResponseWriter, req *http.Request, authData *serviceauth.ImqsAuthResponse, target *targetPassThroughAuth) bool {
	if authData == nil {
		log.Errorf("For Yellowfin transparent authentication, you must also enforce authorization")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return false
	}

	// Get the IMQS user session if present
	c, _ := req.Cookie(serviceauth.Imqsauth_cookie)

	switch req.URL.Path {
	// Used to configure extra parameters present in YF logins
	case "/yellowfin/loginparameters":
		errorResponse := func(err error) {
			log.Errorf("Error parsing yf login paramters: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		bodyData, err := ioutil.ReadAll(req.Body)
		if err != nil {
			errorResponse(err)
			return false
		}
		var params yellowfinLoginParameters
		err = json.Unmarshal(bodyData, &params)
		if err != nil {
			errorResponse(err)
			return false
		}

		// Invalidate user token by expiring the current session.
		// We also preset a new future session with the given YF parameters.
		target.lock.Lock()
		target.tokenMap[authData.Identity] = &yellowfinToken{Expires: time.Now().Add(-1 * time.Second), Parameters: params}
		target.lock.Unlock()

		return false // do not forward this to YF

	// This is actually the normal IMQS8 logout call routed to here.
	// This is necessary to so that we can inject any YF session cookies we might have,
	// before forwarding the logout call to the Auth system.
	// This is required to gracefully logout YF with IMQS.
	case "/yellowfin/logout":
		logoutReq, err := http.NewRequest("POST", serviceauth.Imqsauth_url+"/logout", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}

		// Copy the IMQS8 session cookie to the new logout call
		if c != nil {
			logoutReq.AddCookie(c)
		}

		target.lock.Lock()
		token_yf, exists := target.tokenMap[authData.Identity].(*yellowfinToken)
		if exists {
			// Add the stored YF session to the logout then delete the session on router
			injectYellowfinCookies(logoutReq, token_yf)
			delete(target.tokenMap, authData.Identity)
		}
		target.lock.Unlock()

		logoutResp, err := http.DefaultClient.Do(logoutReq)
		if err != nil {
			log.Errorf("Error logging out of IMQS", err)
			http.Error(w, err.Error(), http.StatusGatewayTimeout)
			return false
		}
		defer logoutResp.Body.Close()

		return false // do not forward this to YF

	// The front-end with an open Iframe to YF will keep polling to check if it is
	// the session currently allowed to access YF. If another instance is opened with the same user,
	// that instance's session will get access, and the first Iframe should exit and go to IMQS home page.
	case "/yellowfin/checksession":
		target.lock.RLock()
		token_yf, exists := target.tokenMap[authData.Identity].(*yellowfinToken)
		if !exists || token_yf.UserSession == "" {
			// No session exists - We still want onSuccess in the front-end, thus we write 201.
			w.WriteHeader(201)
		} else {
			fmt.Fprintf(w, "%s", token_yf.UserSession)
		}
		target.lock.RUnlock()

		return false // do not forward this to YF

	default:
	}

	// The acquisition of a new cookie is the somewhat nontrivial case,
	// because we need to ensure that we don't try and log a person in from more than one
	// concurrent thread.
	for start := time.Now(); time.Now().Sub(start).Seconds() < 15; {
		// -- Fetch cached token --
		done := false
		target.lock.RLock()
		token_yf, exists := target.tokenMap[authData.Identity].(*yellowfinToken)
		yfLoginparams := yellowfinLoginParameters{}
		if exists {
			// If the YF session expires, we will have a saved copy of the
			// login parameters ready for the next login.
			yfLoginparams = token_yf.Parameters

			// We only forward request if session valid and not expired.
			if token_yf.Expires.After(time.Now()) && token_yf.UserSession == c.Value {
				done = true
				injectYellowfinCookies(req, token_yf)
			}
		}
		target.lock.RUnlock()
		if done {
			return true
		}

		// -- User not logged in or session expired. Acquire new token --

		// Acquire a lock on the USER who is trying to login to Yellowfin
		haveUserLock := false
		target.lock.Lock()
		if !target.tokenLock[authData.Identity] {
			target.tokenLock[authData.Identity] = true
			haveUserLock = true
		}
		target.lock.Unlock()

		if haveUserLock {
			token := authYellowfinLogin(log, w, req, authData, yfLoginparams)
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

func authYellowfinLogin(log *log.Logger, w http.ResponseWriter, req *http.Request, authData *serviceauth.ImqsAuthResponse, parameters yellowfinLoginParameters) *yellowfinToken {
	paramsBytes, err := json.Marshal(parameters)
	if err != nil {
		log.Errorf("Error logging in to yellowfin. Login parameters Invalid: %v", err)
		http.Error(w, "Error loggin in to yellowfin", http.StatusInternalServerError)
		return nil
	}
	authReq, err := ms_http.NewRequest("POST", serviceauth.Imqsauth_url+"/login_yellowfin", bytes.NewBuffer(paramsBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	headAuth := req.Header.Get("Authorization")
	if headAuth != "" {
		authReq.Header.Set("Authorization", headAuth)
	}
	cookieSession, _ := req.Cookie(serviceauth.Imqsauth_cookie)
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

	token := &yellowfinToken{
		Expires: time.Now().Add(yellowfinTokenLifetime),
	}
	for _, c := range authResp.Cookies() {
		switch c.Name {
		case "JSESSIONID":
			token.JSESSIONID = c.Value
		case "IPID":
			token.IPID = c.Value
		}
	}

	// Used to keep track of which session has control over a user's single allowed YF session
	if cookieSession != nil {
		token.UserSession = cookieSession.Value
	}

	if token.JSESSIONID != "" && token.IPID != "" {
		log.Infof("Transparent login to yellowfin: %v", authData.Identity)
		return token
	}

	log.Errorf("Error logging in to yellowfin. Not enough cookies. (JSESSIONID='%v' IPID='%v')", token.JSESSIONID, token.IPID)
	http.Error(w, "Error loggin in to yellowfin", http.StatusInternalServerError)

	return nil
}
