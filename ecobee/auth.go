package ecobee

// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	coreV1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// This file contains authentication related functions and structs.

// Scopes defines the scopes we request from the API.
var Scopes = []string{"smartRead", "smartWrite"}

type tokenSource struct {
	token                oauth2.Token
	clientID, secretName string
	secretsClient        coreV1.SecretInterface
}

func TokenSource(clientID, secretName, namespace string) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, newTokenSource(clientID, secretName, namespace))
}

func newTokenSource(clientID, secretName, namespace string) *tokenSource {
	// get kubernetes client
	var config *rest.Config
	if _, err := os.Stat("/var/run/secrets/kubernetes.io"); !os.IsNotExist(err) {
		// we are running inside a kubernetes cluster, use in-cluster config
		config, err = rest.InClusterConfig()
		if err != nil {
			fmt.Println("Unable to create in-cluster config")
			panic(err.Error())
		}
		// ignore namespace value passed in, use namespace of pod
		ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			panic(err.Error())
		}
		namespace = string(ns)
	} else {
		// we are not in a cluster, expect kube config file in $HOME dir
		kubeconfig := os.Getenv("HOME") + "/.kube/config"
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			fmt.Println("Unable to create the out-of-cluster config")
			panic(err.Error())
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Println("Unable to create kubernetes clientset")
		panic(err.Error())
	}

	// get secrets client
	secCli := clientset.CoreV1().Secrets(namespace)

	// ensure the secret exists!
	secret, err := secCli.Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("(newTokenSource) Unable to get secret '%s' in '%s' namespace", secretName, namespace)
		panic(err.Error())
	}

	// check that we have the access and refresh token. if not, start fresh
	if secret.Data["access_token"] == nil || secret.Data["refresh_token"] == nil {
		return &tokenSource{clientID: clientID, secretName: secretName, secretsClient: secCli}
	}

	secret_data := make(map[string]string)
	secret_data["access_token"] = string(secret.Data["access_token"])
	secret_data["token_type"] = string(secret.Data["token_type"])
	secret_data["refresh_token"] = string(secret.Data["refresh_token"])
	secret_data["expiry"] = string(secret.Data["expiry"])

	secret_data_json, err := json.Marshal(secret_data)
	if err != nil {
		fmt.Println("Unable to marshal data from kubernetes secret")
		panic(err.Error())
	}

	var tok oauth2.Token
	err = json.Unmarshal(secret_data_json, &tok)
	if err != nil {
		panic(err.Error())
	}

	return &tokenSource{clientID: clientID, secretName: secretName, secretsClient: secCli, token: tok}
}

func (ts *tokenSource) save() error {
	s, err := ts.secretsClient.Get(context.TODO(), ts.secretName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("(tokenSource.save) Unable to get secret '%s'", ts.secretName)
		panic(err.Error())
	}

	// insert new token into stringData
	s.StringData = map[string]string{}
	s.StringData["access_token"] = ts.token.AccessToken
	s.StringData["token_type"] = ts.token.TokenType
	s.StringData["refresh_token"] = ts.token.RefreshToken
	// Expiry is a time.Time object. Is there a better way to do this?
	time_string, err := json.Marshal(ts.token.Expiry)
	if err != nil {
		panic(err.Error())
	}
	// if we don't do this then we have literal quotes in the string!
	s.StringData["expiry"] = string(time_string)[1 : len(string(time_string))-1]

	// update secret
	_, err = ts.secretsClient.Update(context.TODO(), s, metav1.UpdateOptions{})

	return err
}

type PinResponse struct {
	EcobeePin string `json:"ecobeePin"`
	Code      string `json:"code"`
}

// Interactive authentication, triggered on initial use of the client
func (ts *tokenSource) firstAuth() error {
	pinResponse, err := ts.authorize()
	if err != nil {
		return err
	}
	fmt.Printf("Pin is %q\nPress <enter> after authorizing it on https://www.ecobee.com/consumerportal in the menu"+
		" under 'My Apps'\n", pinResponse.EcobeePin)
	var input string
	fmt.Scanln(&input)
	return ts.accessToken(pinResponse.Code)
}

// Make a pin request to ecobee and return the pin and code
func (ts *tokenSource) authorize() (*PinResponse, error) {
	uv := url.Values{
		"response_type": {"ecobeePin"},
		"client_id":     {ts.clientID},
		"scope":         {strings.Join(Scopes, ",")},
	}
	u := url.URL{
		Scheme:   "https",
		Host:     "api.ecobee.com",
		Path:     "authorize",
		RawQuery: uv.Encode(),
	}

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("error retrieving response: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid server response: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %s", err)
	}

	var r PinResponse
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %s", err)
	}
	return &r, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // nonstandard
	TokenType    string `json:"token_type"`
}

func (tr *tokenResponse) Token() oauth2.Token {
	tok := oauth2.Token{
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}
	return tok
}

func (ts *tokenSource) accessToken(code string) error {
	return ts.getToken(url.Values{
		"grant_type": {"ecobeePin"},
		"client_id":  {ts.clientID},
		"code":       {code},
	})
}
func (ts *tokenSource) refreshToken() error {
	return ts.getToken(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {ts.clientID},
		"refresh_token": {ts.token.RefreshToken},
	})
}

func (ts *tokenSource) getToken(uv url.Values) error {
	u := url.URL{
		Scheme:   "https",
		Host:     "api.ecobee.com",
		Path:     "token",
		RawQuery: uv.Encode(),
	}
	resp, err := http.PostForm(u.String(), nil)
	if err != nil {
		return fmt.Errorf("error POSTing request: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("invalid server response: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %s", err)
	}

	var r tokenResponse
	err = json.Unmarshal(body, &r)
	if err != nil {
		return fmt.Errorf("error unmarshalling response: %s", err)
	}

	ts.token = r.Token()
	if !ts.token.Valid() {
		return fmt.Errorf("invalid token")
	}
	err = ts.save()
	if err != nil {
		return fmt.Errorf("error saving token: %s", err)
	}
	return nil
}

func (ts *tokenSource) Token() (*oauth2.Token, error) {

	if !ts.token.Valid() {
		if len(ts.token.RefreshToken) > 0 {
			err := ts.refreshToken()
			if err != nil {
				return nil, fmt.Errorf("error refreshing token: %s", err)
			}
		} else {
			err := ts.firstAuth()
			if err != nil {
				return nil, fmt.Errorf("error on initial authentication: %s", err)
			}
		}
	}
	return &ts.token, nil
}

// Client represents the Ecobee API client.
type Client struct {
	*http.Client
}

// NewClient creates a Ecobee API client for the specific clientID
// (Application Key).  Use the Ecobee Developer Portal to create the
// Application Key.
// (https://www.ecobee.com/consumerportal/index.html#/dev)
func NewClient(clientID, secretName string, namespace ...string) *Client {
	ns := "default"
	if len(namespace) > 0 {
		ns = namespace[0]
	}
	return &Client{oauth2.NewClient(
		context.Background(), TokenSource(clientID, secretName, ns))}
}

// Authorize retrieves an ecobee Pin and Code, allowing calling code to present them to the user
// outside of the ecobee request context.
// This is useful when non-interactive authorization is required.
// For example: an app being deployed and authorized using ansible, which does not support interacting with commands.
func Authorize(clientID string) (*PinResponse, error) {
	return newTokenSource(clientID, "", "").authorize()
}

// SaveToken retreives a new token from ecobee and saves it to the auth cache
// after a pin/code combination has been added by an ecobee user.
func SaveToken(clientID, secretName, code string, namespace ...string) error {
	ns := "default"
	if len(namespace) > 0 {
		ns = namespace[0]
	}
	return newTokenSource(clientID, secretName, ns).accessToken(code)
}
