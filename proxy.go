// Package main /*
package main

/*
MIT License

Copyright (c) 2022 David Lukac <david.lukac@users.noreply.github.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	ProxyPortEnvVar                    = "PROXY_PORT"
	ProxyBackendEnvVar                 = "PROXY_BACKEND"
	ProxyBackendIsSSLEnvVar            = "PROXY_BACKEND_IS_SSL"
	ProxyBackendTrustedCertPathEnvVar  = "PROXY_BACKEND_CERT_FILE"
	ProxyCertPathEnvVar                = "PROXY_CERT_FILE"
	ProxyCertKeyPathEnvVar             = "PROXY_CERT_KEY_FILE"
	ProxyLogLevelEnvVar                = "PROXY_LOG_LEVEL"
	ProxyIsSSLEnvVar                   = "PROXY_IS_SSL"
	DefaultProxyPort                   = int64(8080)
	DefaultSSLProxyPort                = int64(8443)
	DefaultLogLevel                    = log.InfoLevel
	DefaultCredentialsCacheTTLSMinutes = 1
)

var CacheEvictionReasons = map[ttlcache.EvictionReason]string{
	ttlcache.EvictionReasonDeleted:         "deleted",
	ttlcache.EvictionReasonCapacityReached: "max cache capacity reached",
	ttlcache.EvictionReasonExpired:         "expired",
}

type Proxy struct {
	Backend                *url.URL
	BackendTrustedCertFile string
	ProxyCertFile          string
	ProxyCertKeyFile       string
	IsSSLProxy             bool
	IsSSLBackend           bool
	Instance               *httputil.ReverseProxy
	rootCAs                *x509.CertPool
	connections            *ttlcache.Cache[string, BasicAuthCredentials]
}

type BasicAuthCredentials struct {
	Username string
	Password string
}

type RequestBody struct {
	Info            RequestBodyInfo `json:"info"`
	ConnectionID    string          `json:"connectionId"`
	StatementHandle StatementHandle `json:"statementHandle"`
}

type RequestBodyInfo struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type StatementHandle struct {
	ConnectionID string `json:"connectionId"`
}

// GetEvictionReason returns cache eviction reason as a string.
func GetEvictionReason(reason ttlcache.EvictionReason) string {
	if val, found := CacheEvictionReasons[reason]; found {
		return val
	}
	return "unknown"
}

func (p *Proxy) Init() {
	p.connections = ttlcache.New[string, BasicAuthCredentials](ttlcache.WithTTL[string, BasicAuthCredentials](DefaultCredentialsCacheTTLSMinutes * time.Minute))

	p.connections.OnInsertion(func(ctx context.Context, item *ttlcache.Item[string, BasicAuthCredentials]) {
		log.Debugf("Inserting credentials for connection ID %s, valid until %s", item.Key(), item.ExpiresAt().Format(time.RFC3339))
	})

	p.connections.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[string, BasicAuthCredentials]) {
		log.Infof("Dropping credentials for connection ID %s, reason: %s", item.Key(), GetEvictionReason(reason))
	})

	go p.connections.Start()

	proxy := httputil.NewSingleHostReverseProxy(p.Backend)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		p.requestHandler(req)
	}

	proxy.ModifyResponse = p.responseHandler()

	p.Instance = proxy
	log.Infof("Setting up reverse proxy for backend %s", p.Backend)

	p.setupTrustedCert()
}

func (p *Proxy) setupTrustedCert() {
	if p.Instance == nil {
		err := "Uninitialized proxy instance!"
		log.Fatalf(err)
		panic(err)
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		log.Infof("Initializing empty CA pool...")
		rootCAs = x509.NewCertPool()
	}
	p.rootCAs = rootCAs

	certs, err := ioutil.ReadFile(p.BackendTrustedCertFile)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", p.BackendTrustedCertFile, err)
		panic(err)
	}

	if ok := p.rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("No certs appended, using system certs only")
	}
	log.Infof("Added %s to trusted certificates.", p.BackendTrustedCertFile)

	defaultClient := http.DefaultClient
	defaultClient.Transport = http.DefaultTransport
	defaultClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: rootCAs}

	p.Instance.Transport = defaultClient.Transport
}

func (p *Proxy) requestHandler(req *http.Request) {
	log.Infof("[requestHandler] remoteAddr=\"%s\" @timestamp=\"%s\" request=\"%s\" method=\"%s\" referer=\"%s\" userAgent=\"%s\"", req.RemoteAddr, time.Now().Format(time.RFC3339), req.URL, req.Method, req.Referer(), req.UserAgent())

	req.Header.Set("X-Proxy", "druid-auth-proxy")

	username, password, ok := req.BasicAuth()
	log.Debugf("[requestHandler] Basic auth is set to %s:%s [%t]", username, obfuscatePassword(password), ok)
	if ok {
		// An early return in case basic auth is already set.
		log.Infof("[requestHandler] Basic auth is already set, nothing to do - skipping!")
		return
	}

	// -----------------------------------------------------------------------------------------------------------------

	if req.Body == nil {
		log.Infof("[requestHandler] Request body is empty - nothing to extract credentials from - skipping the rest!")
		return
	}

	// -----------------------------------------------------------------------------------------------------------------

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Errorf("Unable to get body from request.")
	}

	log.Tracef("[requestHandler] Body: %s", body)

	var requestBodyStruct RequestBody
	if err = json.Unmarshal(body, &requestBodyStruct); err != nil {
		log.Errorf("%t", err)
	}

	if requestBodyStruct.ConnectionID == "" && requestBodyStruct.StatementHandle.ConnectionID != "" {
		requestBodyStruct.ConnectionID = requestBodyStruct.StatementHandle.ConnectionID
		log.Debugf("[requestHandler] Using connectionID %s from 'statementHandle'", requestBodyStruct.ConnectionID)
	}

	if len(requestBodyStruct.Info.User) > 0 && len(requestBodyStruct.Info.Password) > 0 {
		log.Infof("[requestHandler] Connection ID [%s]: saving credentials for future use for %d seconds", requestBodyStruct.ConnectionID, -1)
		p.connections.Set(requestBodyStruct.ConnectionID, BasicAuthCredentials{
			Username: requestBodyStruct.Info.User,
			Password: requestBodyStruct.Info.Password,
		}, ttlcache.DefaultTTL)
	} else {
		log.Infof("[requestHandler] Connection ID [%s]: no credentials were provided.", requestBodyStruct.ConnectionID)
	}

	log.Debugf("[requestHandler] Basic auth credentials for connection ID %s: %s:%s", requestBodyStruct.ConnectionID,
		p.connections.Get(requestBodyStruct.ConnectionID).Value().Username, obfuscatePassword(p.connections.Get(requestBodyStruct.ConnectionID).Value().Password))

	if credentialsItem := p.connections.Get(requestBodyStruct.ConnectionID); credentialsItem != nil {
		log.Infof("[requestHandler] Connection ID [%s]: reusing credentials from memory", requestBodyStruct.ConnectionID)
		req.SetBasicAuth(credentialsItem.Value().Username, credentialsItem.Value().Password)
	} else {
		log.Errorf("[requestHandler] Connection ID [%s]: no credentials found for this connection!", requestBodyStruct.ConnectionID)
	}

	// Set the body back after we extracted the credentials.
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
}

func (p *Proxy) responseHandler() func(*http.Response) error {
	return func(resp *http.Response) error {
		log.Debugf("[responseHandler] Status: %s", resp.Status)
		return nil
	}
}

// ProxyRequestHandler handles the http request using proxy
func (p *Proxy) ProxyRequestHandler() func(http.ResponseWriter, *http.Request) {
	if p.Instance == nil {
		err := "Uninitialized proxy instance!"
		log.Fatalf(err)
		panic(err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		p.Instance.ServeHTTP(w, r)
	}
}

// GetBackendURLFromEnvVar get and parse proxy backend URL from ProxyBackendEnvVar environment variable.
func GetBackendURLFromEnvVar() (*url.URL, error) {
	var err error
	var backend string
	var backendURL *url.URL

	backend = os.Getenv(ProxyBackendEnvVar)
	if backend == "" {
		err = fmt.Errorf("empty backend URL environment variable (%s)", ProxyBackendEnvVar)
		return nil, err
	}

	backendURL, err = url.Parse(backend)
	if err != nil {
		return nil, err
	}

	return backendURL, nil
}

// GetBoolFromEnvVar reads given environment variable and parses it as bool. Provides bool value whether the variable
// was set at all as second return value.
func GetBoolFromEnvVar(e string) (bool, bool) {
	envVarValue, envVarExists := os.LookupEnv(e)
	for _, needle := range []string{"1", "t", "y", "true", "yes", "yeah", "yup", "certainly", "uh-huh"} {
		if strings.ToLower(envVarValue) == strings.ToLower(needle) {
			return true, envVarExists
		}
	}
	return false, envVarExists
}

// GetProxyPortFromEnvVar parse port environment variable, if empty provides default based on isSSLProxy parameter.
// Validates parsed port whether in range of 1-65535.
func GetProxyPortFromEnvVar(isSSLProxy bool) (int64, error) {
	proxyPort := os.Getenv(ProxyPortEnvVar)
	if proxyPort == "" {
		port := DefaultProxyPort
		if isSSLProxy {
			port = DefaultSSLProxyPort
		}
		log.Infof("Proxy port not provided in %s environment variable - using default: %d", ProxyPortEnvVar, port)
		return port, nil
	}
	port, err := strconv.ParseInt(proxyPort, 10, 64)
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		err = fmt.Errorf("invalid port number %d, valid range is 1-65535", port)
		return 0, err
	}

	return port, nil
}

// GetFilePathFromEnvVar reads environment variable expecting its contents to point to an existing file.
func GetFilePathFromEnvVar(envVar string) (string, error) {
	var err error

	f := os.Getenv(envVar)
	if f == "" {
		err = fmt.Errorf("provided environment variable %s is empty", envVar)
		return "", err
	}

	if _, err := os.Stat(f); os.IsNotExist(err) {
		return "", err
	}

	return f, nil
}

func main() {
	// Set log level either from environment variable or to default.
	if logLevel, err := log.ParseLevel(os.Getenv(ProxyLogLevelEnvVar)); err == nil {
		log.SetLevel(logLevel)
	} else {
		log.SetLevel(DefaultLogLevel)
	}
	log.Infof("Log level is %s", log.GetLevel())

	backendURL, err := GetBackendURLFromEnvVar()
	if err != nil {
		log.Fatalf(err.Error())
		panic(err)
	}

	isSSLProxyVar, isSSLProxyVarSet := GetBoolFromEnvVar(ProxyIsSSLEnvVar)
	isSSLBackendVar, isSSLBackendVarSet := GetBoolFromEnvVar(ProxyBackendIsSSLEnvVar)

	// First determine whether the backend is SSL.
	isSSLBackend := false
	// If ProxyBackendIsSSLEnvVar is not set but backend has https scheme, we can assume backend is SSL.
	if strings.ToLower(backendURL.Scheme) == "https" && isSSLBackendVarSet == false {
		log.Infof("Assuming backend is SSL because %s enviornment variable is not set but backend scheme is https", ProxyBackendIsSSLEnvVar)
		isSSLBackend = true
	}
	// .. or if ProxyBackendIsSSLEnvVar is explicitly set to true.
	if isSSLBackendVar {
		isSSLBackend = true
	}
	sslBoolMap := map[bool]string{true: "SSL", false: "non-SSL"}
	log.Infof("Expecting %s backend ...", sslBoolMap[isSSLBackend])

	// Determine whether the proxy is serving SSL.
	isSSLProxy := false
	// If ProxyIsSSLEnvVar is not defined and backend is SSL, we assume the proxy is SSL as well.
	if isSSLProxyVarSet == false && isSSLBackend {
		log.Infof("Assuming proxy is serving SSL because %s environment varirable is not set but backend is SSL", ProxyIsSSLEnvVar)
		isSSLProxy = true
	}
	// ... or if ProxyIsSSLEnvVar explicitly is set to true.
	if isSSLProxyVar {
		isSSLProxy = true
	}
	log.Infof("Serving as %s proxy ...", sslBoolMap[isSSLProxy])

	proxyPort, err := GetProxyPortFromEnvVar(isSSLProxy)
	if err != nil {
		log.Fatalf(err.Error())
		panic(err)
	}
	log.Infof("Proxy will listen on port %d", proxyPort)

	var backendTrustedCertFile string
	if isSSLBackend {
		backendTrustedCertFile, err = GetFilePathFromEnvVar(ProxyBackendTrustedCertPathEnvVar)
		if err != nil {
			log.Fatalf(err.Error())
			panic(err)
		}
		log.Infof("Using trusted backend SSL certificate from %s", backendTrustedCertFile)
	}

	var proxyCertFile, proxyCertKeyFile string
	if isSSLProxy {
		proxyCertFile, err = GetFilePathFromEnvVar(ProxyCertPathEnvVar)
		if err != nil {
			log.Fatalf(err.Error())
			panic(err)
		}
		proxyCertKeyFile, err = GetFilePathFromEnvVar(ProxyCertKeyPathEnvVar)
		if err != nil {
			log.Fatalf(err.Error())
			panic(err)
		}
		log.Infof("Using proxy SSL certificate and certificate key from %s and %s", proxyCertFile, proxyCertKeyFile)
	}

	p := Proxy{
		Backend:                backendURL,
		BackendTrustedCertFile: backendTrustedCertFile,
		ProxyCertFile:          proxyCertFile,
		ProxyCertKeyFile:       proxyCertKeyFile,
		IsSSLProxy:             isSSLProxy,
		IsSSLBackend:           isSSLBackend,
	}
	p.Init()

	http.HandleFunc("/", p.ProxyRequestHandler())
	if p.IsSSLProxy {
		log.Infof("Starting the proxy for %s with TLS", p.Backend)
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", proxyPort), p.ProxyCertFile, p.ProxyCertKeyFile, nil))
	} else {
		log.Infof("Starting the proxy for %s", p.Backend)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), nil))
	}
}

// obfuscatePassword hides contents of the password except first and last letter.
func obfuscatePassword(pwd string) string {
	first := ""
	fill := ""
	last := ""
	if len(pwd) > 0 {
		first = pwd[0:1]
		fill = "****"
		last = pwd[len(pwd)-1:]
	}
	return fmt.Sprintf("%s%s%s", first, fill, last)
}
