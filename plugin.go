package traefik_api_key_auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type Config struct {
	AuthenticationHeader       bool     `json:"authenticationHeader,omitempty"`
	AuthenticationHeaderName   string   `json:"headerName,omitempty"`
	BearerHeader               bool     `json:"bearerHeader,omitempty"`
	BearerHeaderName           string   `json:"bearerHeaderName,omitempty"`
	QueryParam                 bool     `json:"queryParam,omitempty"`
	QueryParamName             string   `json:"queryParamName,omitempty"`
	PathSegment                bool     `json:"pathSegment,omitempty"`
	RemoveQueryParamsOnSuccess bool		`json:"removeQueryParamsOnSuccess,omitempty"`
	Keys                       []string `json:"keys,omitempty"`
	RemoveHeadersOnSuccess     bool     `json:"removeHeadersOnSuccess,omitempty"`
	InternalForwardHeaderName  string   `json:"internalForwardHeaderName,omitempty"`
	InternalErrorRoute         string   `json:"internalErrorRoute,omitempty"`
}

type Response struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func CreateConfig() *Config {
	return &Config{
		AuthenticationHeader:      true,
		AuthenticationHeaderName:  "X-API-KEY",
		BearerHeader:              true,
		BearerHeaderName:          "Authorization",
		QueryParam:                true,
		QueryParamName:            "token",
		PathSegment:               true,
		RemoveQueryParamsOnSuccess:true,
		Keys:                      make([]string, 0),
		RemoveHeadersOnSuccess:    true,
		InternalForwardHeaderName: "",
		InternalErrorRoute:        "",
	}
}

type KeyAuth struct {
	next                       http.Handler
	authenticationHeader       bool
	authenticationHeaderName   string
	bearerHeader               bool
	bearerHeaderName           string
	queryParam                 bool
	queryParamName             string
	pathSegment                bool
	removeQueryParamsOnSuccess bool
	keys                       []string
	removeHeadersOnSuccess     bool
	internalForwardHeaderName  string
	internalErrorRoute         string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("Creating plugin: %s instance: %+v, ctx: %+v\n", name, *config, ctx)

	// check for empty keys
	if len(config.Keys) == 0 {
		return nil, fmt.Errorf("must specify at least one valid key")
	}

	// check at least one method is set
	if !config.AuthenticationHeader && !config.BearerHeader && !config.QueryParam && !config.PathSegment {
		return nil, fmt.Errorf("at least one method must be true")
	}

	return &KeyAuth{
		next:                       next,
		authenticationHeader:       config.AuthenticationHeader,
		authenticationHeaderName:   config.AuthenticationHeaderName,
		bearerHeader:               config.BearerHeader,
		bearerHeaderName:           config.BearerHeaderName,
		queryParam:                 config.QueryParam,
		queryParamName:             config.QueryParamName,
		pathSegment:                config.PathSegment,
		removeQueryParamsOnSuccess: config.RemoveQueryParamsOnSuccess,
		keys:                       config.Keys,
		removeHeadersOnSuccess:     config.RemoveHeadersOnSuccess,
		internalForwardHeaderName:  config.InternalForwardHeaderName,
		internalErrorRoute:         config.InternalErrorRoute,
	}, nil
}

// contains takes an API key and compares it to the list of valid API keys. The return value notes whether the
// key is in the valid keys
// list or not.
func contains(key string, validKeys []string, exact bool) string {
	for _, a := range validKeys {
		if exact {
			if a == key {
				return a
			}
		} else {
			if strings.Contains(key, a) {
				return a
			}
		}
	}
	return ""
}

// bearer takes an API key in the `Authorization: Bearer $token` form and compares it to the list of valid keys.
// The token/key is extracted from the header value. The return value notes whether the key is in the valid keys
// list or not.
func bearer(key string, validKeys []string) string {
	re, _ := regexp.Compile(`Bearer\s(?P<key>[^$]+)`)
	matches := re.FindStringSubmatch(key)

	// If no match found the value is in the wrong form.
	if matches == nil {
		return ""
	}

	// If found extract the key and compare it to the list of valid keys
	keyIndex := re.SubexpIndex("key")
	extractedKey := matches[keyIndex]
	return contains(extractedKey, validKeys, true)
}

func (ka *KeyAuth) ok(rw http.ResponseWriter, req *http.Request, key string) {
	os.Stdout.WriteString(fmt.Sprintf("INFO: traefik_api_key_auth KEY %s URL %s\n", key, req.URL))
	if ka.internalForwardHeaderName != "" {
		req.Header.Add(ka.internalForwardHeaderName, key)
	}
	req.RequestURI = req.URL.RequestURI()
	ka.next.ServeHTTP(rw, req)
}

func (ka *KeyAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check authentication header for valid key
	if ka.authenticationHeader {
		var matchedKey = contains(req.Header.Get(ka.authenticationHeaderName), ka.keys, true)
		if matchedKey != "" {
			// X-API-KEY header contains a valid key
			if ka.removeHeadersOnSuccess {
				req.Header.Del(ka.authenticationHeaderName)
			}
			ka.ok(rw, req, matchedKey)
			return
		}
	}

	// Check authorization header for valid Bearer
	if ka.bearerHeader {
		var matchedKey = bearer(req.Header.Get(ka.bearerHeaderName), ka.keys)
		if matchedKey != "" {
			// Authorization header contains a valid Bearer token
			if ka.removeHeadersOnSuccess {
				req.Header.Del(ka.bearerHeaderName)
			}
			ka.ok(rw, req, matchedKey)
			return
		}
	}

	// Check query param for valid key
	if ka.queryParam {
		var qs = req.URL.Query()
		var matchedKey = contains(qs.Get(ka.queryParamName), ka.keys, true)
		if matchedKey != "" {
			if ka.removeQueryParamsOnSuccess{
				qs.Del(ka.queryParamName)
			}
			req.URL.RawQuery = qs.Encode()
			ka.ok(rw, req, matchedKey)
			return
		}
	}

	// Check URL path for valid key in segment
	if ka.pathSegment {
		var matchedKey = contains(req.URL.Path, ka.keys, false)
		if matchedKey != "" {
			ka.ok(rw, req, matchedKey)
			return
		}
	}

	if ka.internalErrorRoute != "" {
		req.URL.Path = ka.internalErrorRoute
		req.URL.RawQuery = ""
		return
	}

	var response = Response{
		Message:    "Invalid or missing API Key",
		StatusCode: http.StatusForbidden,
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(response.StatusCode)

	// If no headers or invalid key, return 403
	if err := json.NewEncoder(rw).Encode(response); err != nil {
		// If response cannot be written, log error
		fmt.Printf("Error when sending response to an invalid key: %s", err.Error())
	}
}
