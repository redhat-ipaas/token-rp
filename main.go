//    Copyright 2017 Red Hat, Inc.
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/google/go-github/github"
	"github.com/vulcand/oxy/forward"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"

	"github.com/syndesisio/token-rp/pkg/version"
)

const (
	discoveryPath = "/.well-known/openid-configuration"

	githubIDPType    = "github"
	openshiftIDPType = "openshift"
)

var (
	issuerURLFlag               urlFlag
	proxyURLFlag                urlFlag
	clientID                    string
	idpAlias                    string
	idpType                     string
	serverCertFile              string
	serverKeyFile               string
	insecureSkipVerify          bool
	versionFlag                 bool
	caCerts                     stringSliceFlag
	identityServerFlag          urlFlag
	verbose                     bool
	providerConfigRetryInterval time.Duration
	providerConfigRetryMax      int

	flagSet = flag.NewFlagSet("token-rp", flag.ContinueOnError)

	gitRequestRegexp = regexp.MustCompile(`/(git-upload-pack|git-receive-pack|info/refs|HEAD|objects/info/alternates|objects/info/http-alternates|objects/info/packs|objects/info/[^/]*|objects/[0-9a-f]{2}/[0-9a-f]{38}|objects/pack/pack-[0-9a-f]{40}\\.pack|objects/pack/pack-[0-9a-f]{40}\\.idx)$`)
)

func init() {
	flagSet.Var(&issuerURLFlag, "issuer-url", "URL to OpenID Connect discovery document")
	flagSet.Var(&proxyURLFlag, "proxy-url", "URL to proxy requests to")
	flagSet.StringVar(&clientID, "client-id", "", "OpenID Connect client ID to verify")
	flagSet.StringVar(&idpAlias, "provider-alias", "", "Keycloak provider alias to replace authorization token with")
	flagSet.StringVar(&idpType, "provider-type", "", "Type of Keycloak IDP (currently supports openshift and github only)")
	flagSet.StringVar(&serverCertFile, "tls-cert", "", "Path to PEM-encoded certificate to use to serve over TLS")
	flagSet.StringVar(&serverKeyFile, "tls-key", "", "Path to PEM-encoded key to use to serve over TLS")
	flagSet.BoolVar(&versionFlag, "version", false, "Output version and exit")
	flagSet.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "If insecureSkipVerify is true, TLS accepts any certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing.")
	flagSet.Var(&caCerts, "ca-cert", "Extra root certificate(s) that clients use when verifying server certificates")
	flagSet.Var(&identityServerFlag, "identity-server-url", "URL to identity server")
	flagSet.BoolVar(&verbose, "verbose", false, "Verbose logging.")
	flagSet.DurationVar(&providerConfigRetryInterval, "provider-config-retry-interval", 10*time.Second, "retry interval if provider config is unavailable")
	flagSet.IntVar(&providerConfigRetryMax, "provider-config-retry-max", -1, "max retries if provider config is unavailable")
	// where does log entry come from
	log.SetFlags(log.Flags() | log.Lshortfile)
}

func main() {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if versionFlag {
		fmt.Printf("%s %s (%s)\n", filepath.Base(os.Args[0]), version.AppVersion, version.BuildDate)
		os.Exit(0)
	}

	prodConfig := zap.NewProductionConfig()
	prodConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	prodLogger, _ := prodConfig.Build()
	defer prodLogger.Sync() // flushes buffer, if any
	logger := prodLogger.Sugar()

	if idpType != openshiftIDPType && idpType != githubIDPType {
		logger.Fatalw(
			"Unknown provider-type",
			"providerType", idpType,
		)
	}
	proxyTargetTokenType := "Bearer"
	if idpType == githubIDPType {
		proxyTargetTokenType = "token"
	}

	if len(serverCertFile) > 0 && len(serverKeyFile) == 0 {
		fmt.Fprint(os.Stderr, "tls-cert specified with no tls-key\n")
		os.Exit(2)
	}
	if len(serverCertFile) == 0 && len(serverKeyFile) > 0 {
		fmt.Fprint(os.Stderr, "tls-key specified with no tls-cert\n")
		os.Exit(2)
	}

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		logger.Fatalw(
			"Failed to create cert pool",
			"error", err,
		)
	}

	for _, cert := range caCerts {
		certBytes, err := ioutil.ReadFile(cert)
		if err != nil {
			logger.Fatalw(
				"Failed to read CA certificate",
				"file", cert,
				"error", err,
			)
		}
		caCertPool.AppendCertsFromPEM(certBytes)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			RootCAs:            caCertPool,
		},
	}
	hc := &http.Client{
		Transport: tr,
	}

	issuerURL := strings.TrimSuffix(strings.TrimSuffix(issuerURLFlag.String(), discoveryPath), "/")
	var providerConfig oidc.ProviderConfig
	currentAttempt := 0
	for providerConfig.Issuer == nil {
		providerConfig, err = oidc.FetchProviderConfig(hc, issuerURL)
		if err != nil {
			if 0 <= providerConfigRetryMax && providerConfigRetryMax <= currentAttempt {
				logger.Fatalw(
					"Provider config unavailable",
					"error", err,
					"issuerURL", issuerURL,
				)
			}
			logger.Warnw(
				"Provider config unavailable (retrying)",
				"error", err,
				"issuerURL", issuerURL,
			)
			currentAttempt++
			<-time.After(providerConfigRetryInterval)
		}
	}

	oidcClient, err := oidc.NewClient(oidc.ClientConfig{
		HTTPClient:     hc,
		ProviderConfig: providerConfig,
		Credentials: oidc.ClientCredentials{
			ID: clientID,
		},
	})
	if err != nil {
		logger.Fatalw(
			"Failed to create new OIDC client",
			"error", err,
		)
	}

	syncStop := oidcClient.SyncProviderConfig(issuerURL)
	defer close(syncStop)

	fwd, err := forward.New(forward.RoundTripper(tr))
	if err != nil {
		logger.Fatalw(
			"Failed to create new proxy handler",
			"error", err,
		)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		isGitRequest := gitRequestRegexp.MatchString(req.URL.Path)

		var token string

		if isGitRequest {
			_, token, _ = req.BasicAuth()
		} else {
			tokenFromHeader, err := jwtmiddleware.FromFirst(
				tokenFromAuthHeaderWithPrefix("bearer"),
				tokenFromAuthHeaderWithPrefix("token"),
			)(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			token = tokenFromHeader
		}

		if len(token) > 0 {
			jwt, err := jose.ParseJWT(token)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			err = oidcClient.VerifyJWT(jwt)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			retrievedToken, err := retrieveTargetToken(issuerURL, idpAlias, idpType, token, hc)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if isGitRequest {
				if len(retrievedToken) > 0 {
					if idpType == githubIDPType {
						ctx := context.Background()
						ts := oauth2.StaticTokenSource(
							&oauth2.Token{AccessToken: retrievedToken},
						)
						tc := oauth2.NewClient(ctx, ts)

						client := github.NewClient(tc)
						if len(identityServerFlag.Host) > 0 {
							identityServerURL := (url.URL)(identityServerFlag)
							client.BaseURL = &identityServerURL
						}

						// list all repositories for the authenticated user
						user, _, err := client.Users.Get(ctx, "")
						if err != nil {
							fmt.Printf("%v\n", err)
							http.Error(w, err.Error(), http.StatusUnauthorized)
							return
						}

						req.SetBasicAuth(user.GetLogin(), retrievedToken)
					}
				}
			} else {
				req.Header.Set("Authorization", proxyTargetTokenType+" "+retrievedToken)
			}
		}

		proxyURL := (url.URL)(proxyURLFlag)
		req.URL = &proxyURL
		fwd.ServeHTTP(w, req)
	})

	s := &http.Server{
		Addr:    ":8080",
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ErrorLog: log.New(&nopWriter{}, "", log.LstdFlags),
	}

	if len(serverCertFile) > 0 {
		err = s.ListenAndServeTLS(serverCertFile, serverKeyFile)
	} else {
		err = s.ListenAndServe()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v", err)
	}
}

type jsonBrokerToken struct {
	AccessToken string `json:"access_token"`
}

func retrieveTargetToken(issuerURL, idpAlias, idpType, token string, hc *http.Client) (string, error) {
	tokenURL := issuerURL + "/broker/" + idpAlias + "/token"
	tokenReq, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return "", err
	}
	tokenReq.Header.Set("Authorization", "Bearer "+token)
	tokenResp, err := hc.Do(tokenReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = tokenResp.Body.Close() }()

	if tokenResp.StatusCode != 200 {
		return "", fmt.Errorf("unable to retrieve broker token: %s", tokenResp.Status)
	}

	b, err := ioutil.ReadAll(tokenResp.Body)
	if err != nil {
		return "", err
	}

	if idpType == openshiftIDPType {
		var brokerToken jsonBrokerToken
		if err = json.Unmarshal(b, &brokerToken); err != nil {
			return "", err
		}
		if len(brokerToken.AccessToken) > 0 {
			return brokerToken.AccessToken, nil
		}

		return "", fmt.Errorf("missing access token in broker token")
	}

	if idpType == githubIDPType {
		query, err := url.ParseQuery(string(b))
		if err != nil {
			return "", err
		}

		accessToken := query.Get("access_token")
		if len(accessToken) > 0 {
			return accessToken, nil
		}

		return "", fmt.Errorf("missing access token in broker token")
	}

	return "", fmt.Errorf("broker token in unknown format")
}

func tokenFromAuthHeaderWithPrefix(prefix string) jwtmiddleware.TokenExtractor {
	return func(r *http.Request) (string, error) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return "", nil // No error, just no token
		}

		// TODO: Make this a bit more robust, parsing-wise
		authHeaderParts := strings.Split(authHeader, " ")
		if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != prefix {
			return "", nil // No error, just no token
		}

		return authHeaderParts[1], nil
	}
}

type nopWriter struct {
}

func (w *nopWriter) Write(b []byte) (int, error) {
	return len(b), nil
}
