// Copyright 2015 The SayHi Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

var (
	listenAddress = kingpin.Flag(
		"listen-address",
		"Address on which to expose metrics and web interface.",
	).Envar("LISTEN_PORT").Default(":8080").String()

	ctrlAPIAddr = kingpin.Flag(
		"nv-controller-api-svc",
		"neuvector-controller-api-service-address",
	).Default("neuvector-svc-controller").Envar("CTRL_API_SVC").String()

	ctrlAPIPort = kingpin.Flag(
		"nv-controller-port",
		"neuvector-controller-port",
	).Envar("CTRL_API_PORT").String()

	ctrlUserName = kingpin.Flag(
		"nv-controller-username",
		"neuvector-controller-username",
	).Default("admin").Envar("CTRL_USERNAME").String()

	ctrlPassword = kingpin.Flag(
		"nv-controller-password",
		"neuvector-controller-password",
	).Default("admin").Envar("CTRL_PASSWORD").String()

	patternPrefix = kingpin.Flag(
		"pattern-prefix",
		"pattern-prefix",
	).Default("join_token").Envar("ROUTE_PREFIX").String()
)

type JoinTokenCache struct {
	JoinToken string
	ExpiresAt int64
}

type JoinToken struct {
	sync.RWMutex
	ServerAddress string
	Username      string
	Password      string
	Token         *JoinTokenCache
}
type RESTAuthPassword struct {
	Username    string  `json:"username"`
	Password    string  `json:"password"`
	NewPassword *string `json:"new_password,omitempty"`
}

type RESTAuthToken struct {
	Token    string `json:"token"`
	State    string `json:"state"`
	Redirect string `json:"redirect_endpoint"`
}

type RESTAuthData struct {
	Password *RESTAuthPassword `json:"password,omitempty"`
	Token    *RESTAuthToken    `json:"Token,omitempty"`
}
type RESTFedJoinToken struct { // json of the join token that contains master cluster server/port & encrypted join_ticket
	JoinToken string `json:"join_token"`
}

type RESTToken struct {
	Token string `json:"token"`
}

type RESTTokenData struct {
	Token               *RESTToken `json:"token"`
	PwdDaysUntilExpire  int        `json:"password_days_until_expire"`  // negative means we don't know it (for ldap/saml/oidc login).
	PwdHoursUntilExpire int        `json:"password_hours_until_expire"` // the hours part beyond PwdDaysUntilExpire, 0 ~ 23
	NeedToResetPassword bool       `json:"need_to_reset_password"`      // prompt the uer to login again & provide the new password to reset after login
	// If both PwdDaysUntilExpire/PwdDaysUntilExpire are 0, it means the password is already expired
}

// RequestConfig 定义HTTP请求的配置参数
type RequestConfig struct {
	URL               string            // 请求URL (必需)
	Method            string            // HTTP方法 (GET, POST, PUT, DELETE等) (必需)
	Headers           map[string]string // 请求头 (可选)
	Body              interface{}       // 请求体 (可以是结构体、map或[]byte) (可选)
	Timeout           time.Duration     // 请求超时时间 (可选，默认10秒)
	Insecure          bool              // 是否跳过SSL证书验证 (可选)
	ParseResponse     bool              // 是否解析响应体到result参数 (可选)
	BasicAuthUsername string            // 基本认证用户名 (可选)
	BasicAuthPassword string            // 基本认证密码 (可选)
}

// HttpResponse 包含HTTP响应信息
type HttpResponse struct {
	StatusCode int         `json:"status_code,omitempty"` // HTTP状态码
	Body       []byte      `json:"context,omitempty"`     // 原始响应体
	Result     interface{} `json:"result,omitempty"`      // 解析后的响应体 (如果配置了ParseResponse)
}

// SendHTTPRequest 通用的HTTP请求函数
func SendHTTPRequest(config RequestConfig, result interface{}) (*HttpResponse, error) {
	// 设置默认超时时间
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}

	// 准备请求体
	var bodyReader io.Reader
	if config.Body != nil {
		switch v := config.Body.(type) {
		case []byte:
			bodyReader = bytes.NewReader(v)
		case string:
			bodyReader = bytes.NewReader([]byte(v))
		default:
			jsonData, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("marshal error: %w", err)
			}
			bodyReader = bytes.NewReader(jsonData)
		}
	}

	// 创建请求
	req, err := http.NewRequest(config.Method, config.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("new http request error: %w", err)
	}

	// 设置请求头
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	// 如果未设置Content-Type且有请求体，默认设置为JSON
	if _, hasContentType := config.Headers["Content-Type"]; !hasContentType && bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// 设置基本认证
	if config.BasicAuthUsername != "" && config.BasicAuthPassword != "" {
		req.SetBasicAuth(config.BasicAuthUsername, config.BasicAuthPassword)
	}

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: config.Timeout,
	}

	// 配置TLS设置
	if config.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http send error: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body error: %w", err)
	}

	// 创建响应对象
	response := &HttpResponse{
		StatusCode: resp.StatusCode,
		Body:       body,
	}

	// 如果需要解析响应体
	if config.ParseResponse && result != nil {
		response.Result = result
		if err := json.Unmarshal(body, result); err != nil {
			return response, fmt.Errorf("unmarshal error: %w", err)
		}
	}

	return response, nil
}

func (j *JoinToken) requestNewToken() (string, error) {
	restAuthData := RESTAuthData{Password: &RESTAuthPassword{Username: j.Username, Password: j.Password}}

	tokenData := RESTTokenData{}

	config := RequestConfig{
		URL:           fmt.Sprintf("%s/v1/auth", j.ServerAddress),
		Method:        http.MethodPost,
		Body:          restAuthData,
		ParseResponse: true,
		Insecure:      true,
	}

	resp, err := SendHTTPRequest(config, &tokenData)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("/v1/auth: %v, resp: %v", resp.StatusCode, string(resp.Body))
	}

	headers := make(map[string]string)
	headers["X-Auth-Token"] = tokenData.Token.Token
	log.Printf("login success. X-Auth-Token: %v*****", tokenData.Token.Token[:10])

	var restFedJoinToken RESTFedJoinToken
	joinTokenConfig := RequestConfig{
		URL:           fmt.Sprintf("%s/v1/fed/join_token", j.ServerAddress),
		Headers:       headers,
		ParseResponse: true,
		Insecure:      true,
	}
	resp2, err := SendHTTPRequest(joinTokenConfig, &restFedJoinToken)

	if err != nil {
		return "", err
	}

	if resp2.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("/v1/fed/join_token: %v, resp: %v", resp2.StatusCode, string(resp2.Body))
	}

	return restFedJoinToken.JoinToken, nil

}

func (j *JoinToken) updateJoinToken() (string, error) {
	cj := JoinTokenCache{
		// token 实际有效期1h, 此处为缓存中的token有效期30m
		ExpiresAt: time.Now().Add(time.Minute * 30).Unix(),
	}
	token, err := j.requestNewToken()
	if err != nil {
		return "", err
	}

	cj.JoinToken = token
	j.Lock()
	defer j.Unlock()
	j.Token = &cj
	log.Printf("new join token: %v, expires at: %v", j.Token.JoinToken, time.Unix(cj.ExpiresAt, 0).Format(time.RFC3339))
	return token, nil
}

func (j *JoinToken) getJoinToken() (string, error) {
	if j.Token == nil {
		return j.updateJoinToken()
	}
	if time.Now().Unix() < j.Token.ExpiresAt {
		return j.Token.JoinToken, nil
	}

	return j.updateJoinToken()

}

func (j *JoinToken) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type serveHttpResponse struct {
		StatusCode int    `json:"status_code,omitempty"`
		Context    string `json:"context,omitempty"`
	}
	resp := serveHttpResponse{}
	w.Header().Set("Content-Type", "application/json")

	if strings.Contains(r.RequestURI, "flush") {
		token, err := j.updateJoinToken()
		if err != nil || token == "" {
			log.Printf("update join token error: %v", err)
			resp.StatusCode = http.StatusInternalServerError
			resp.Context = "flush failed."
			w.WriteHeader(resp.StatusCode)
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	token, err := j.getJoinToken()
	if err != nil {
		log.Printf("get join token error: %v", err)
		resp.StatusCode = http.StatusInternalServerError
		resp.Context = ""
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(resp)
	} else {
		resp.Context = token
		resp.StatusCode = http.StatusOK
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(resp)
	}

}

func SayHi(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func main() {
	log.SetFlags(23)
	kingpin.Parse()

	*patternPrefix = strings.TrimRight(*patternPrefix, "/")
	*patternPrefix = strings.TrimLeft(*patternPrefix, "/")
	pass := *ctrlPassword
	log.Printf("Parse Config:\nlisten_port=%s\nctrl_addr=%s\nctrl_port=%s\nprefix=%s\nuser=%s\npassword=%s***\n",
		*listenAddress, *ctrlAPIAddr, *ctrlAPIPort, *patternPrefix, *ctrlUserName, pass[:1])

	svcURL := *ctrlAPIAddr

	if !strings.HasPrefix(*ctrlAPIAddr, "http://") && !strings.HasPrefix(*ctrlAPIAddr, "https://") {
		svcURL = fmt.Sprintf("https://%s", *ctrlAPIAddr)
	}

	svcURL = strings.TrimRight(svcURL, "/")

	if *ctrlAPIPort != "" {
		svcURL = fmt.Sprintf("%s:%s", svcURL, *ctrlAPIPort)
	}
	log.Printf("nv ctrl url: %s", svcURL)
	c := JoinToken{
		ServerAddress: svcURL,
		Username:      *ctrlUserName,
		Password:      *ctrlPassword,
	}
	log.Printf("Starting server at %s", *listenAddress)
	http.HandleFunc("/healthz", SayHi)
	http.Handle(fmt.Sprintf("/%s", *patternPrefix), &c)
	http.Handle(fmt.Sprintf("/%s/flush", *patternPrefix), &c)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
