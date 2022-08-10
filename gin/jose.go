package gin

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	auth0 "github.com/auth0-community/go-auth0"
	"github.com/gin-gonic/gin"
	krakendjose "github.com/krakendio/krakend-jose/v2"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	ginlura "github.com/luraproject/lura/v2/router/gin"
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf ginlura.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginlura.HandlerFactory {
	return TokenSignatureValidator(TokenSigner(hf, logger), logger, rejecterF)
}

func TokenSigner(hf ginlura.HandlerFactory, logger logging.Logger) ginlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTSigner]"
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err == krakendjose.ErrNoSignerCfg {
			logger.Debug(logPrefix, "Signer disabled")
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error(logPrefix, "Unable to create the signer:", err.Error())
			return hf(cfg, prxy)
		}

		logger.Debug(logPrefix, "Signer enabled")

		return func(c *gin.Context) {
			proxyReq := ginlura.NewRequest(cfg.HeadersToPass)(c, cfg.QueryString)
			ctx, cancel := context.WithTimeout(c, cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error(logPrefix, "Proxy response:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if response == nil {
				logger.Error(logPrefix, "Empty proxy response")
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if err := krakendjose.SignFields(signerCfg.KeysToSign, signer, response); err != nil {
				logger.Error(logPrefix, "Signing fields:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			for k, v := range response.Metadata.Headers {
				c.Header(k, v[0])
			}
			c.JSON(response.Metadata.StatusCode, response.Data)
		}
	}
}

func TokenSignatureValidator(hf ginlura.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTValidator]"
		if rejecterF == nil {
			rejecterF = new(krakendjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		handler := hf(cfg, prxy)
		scfg, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info(logPrefix, "Validator disabled for this endpoint")
			return handler
		}
		if err != nil {
			logger.Warning(logPrefix, "Unable to parse the configuration:", err.Error())
			return handler
		}

		validator, err := krakendjose.NewValidator(scfg, FromCookie)
		if err != nil {
			logger.Fatal(logPrefix, "Unable to create the validator:", err.Error())
		}

		var aclCheck func(string, map[string]interface{}, []string) bool

		if scfg.RolesKeyIsNested && strings.Contains(scfg.RolesKey, ".") && scfg.RolesKey[:4] != "http" {
			logger.Debug(logPrefix, fmt.Sprintf("Roles will be matched against the nested key: '%s'", scfg.RolesKey))
			aclCheck = krakendjose.CanAccessNested
		} else {
			logger.Debug(logPrefix, fmt.Sprintf("Roles will be matched against the key: '%s'", scfg.RolesKey))
			aclCheck = krakendjose.CanAccess
		}

		var scopesMatcher func(string, map[string]interface{}, []string) bool

		if len(scfg.Scopes) > 0 && scfg.ScopesKey != "" {
			if scfg.ScopesMatcher == "all" {
				logger.Debug(logPrefix, fmt.Sprintf("Constraint added: tokens must contain a claim '%s' with all these scopes: %v", scfg.ScopesKey, scfg.Scopes))
				scopesMatcher = krakendjose.ScopesAllMatcher
			} else {
				logger.Debug(logPrefix, fmt.Sprintf("Constraint added: tokens must contain a claim '%s' with any of these scopes: %v", scfg.ScopesKey, scfg.Scopes))
				scopesMatcher = krakendjose.ScopesAnyMatcher
			}
		} else {
			logger.Debug(logPrefix, "No scope validation required")
			scopesMatcher = krakendjose.ScopesDefaultMatcher
		}

		if scfg.OperationDebug {
			logger.Debug(logPrefix, "Validator enabled for this endpoint. Operation debug is enabled")
		} else {
			logger.Debug(logPrefix, "Validator enabled for this endpoint")
		}

		paramExtractor := extractRequiredJWTClaims(cfg)

		return func(c *gin.Context) {
			token, err := validator.ValidateRequest(c.Request)
			if err != nil {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Unable to validate the token:", err.Error())
				}
				// c.Request.Method => GET
				// c.Request.URL => /v1/new-1657734259452
				// c.Request.Proto => HTTP/1.1
				// c.Request.Host => localhost:8080

				//var jwtHeader string
				//var httpCode int
				//var redirectUri string

				logger.Error("auth code присутсвует:", c.Request.URL.Query()["code"][1], "auth code: ", c.Request.URL.Query()["code"][0])
				if code, ok := c.Request.URL.Query()["code"]; ok {
					url := "https://sso.balance-pl.ru/auth/realms/Staging/protocol/openid-connect/token"
					payload := strings.NewReader(
						"grant_type=authorization_code&" +
							"client_id=krakend-test&" +
							"client_secret=28dfa8db-48f5-4963-a98a-e8003cc2f166&" +
							"code=" + code[0] + "&" +
							"redirect_uri=http://localhost:8080/v1/new-1657734259452")
					req, _ := http.NewRequest(http.MethodPost, url, payload)
					req.Header.Add("content-type", "application/x-www-form-urlencoded")
					res, _ := http.DefaultClient.Do(req)
					defer res.Body.Close()
					body, _ := ioutil.ReadAll(res.Body)
					var data map[string]interface{}
					err := json.Unmarshal([]byte(body), &data)
					if err != nil {
						panic(err)
					}
					fmt.Println("Access token: ", data["access_token"])

					jwtCookie := createJwtCookie(data["access_token"].(string))
					c.Request.Header.Add("Set-Cookie", jwtCookie.String())
					c.Redirect(http.StatusUseProxy, c.Request.Host+c.Request.URL.Path)
				} else {
					redirectUri := "https://sso.balance-pl.ru/auth/realms/Staging/protocol/openid-connect/auth?client_id=krakend-test&redirect_uri=http://localhost:8080/v1/new-1657734259452&response_type=code"
					c.Abort()
					c.Redirect(http.StatusSeeOther, redirectUri)
				}

				// realm: Staging
				// clientID: krakend-test
				// secret: 28dfa8db-48f5-4963-a98a-e8003cc2f166
				// redirect URL: http://localhost:8080/v1/new-1657734259452

				// в ответе код

				// Что реализовано на данный момент и текущая проблема:
				// Внесены исправления в библиотеку krakend-jose во все 3 места проверки валидности/существования токена.
				// Теперь вместе ответа 401, krakend делает редирект на страницу логина keycloak, передавая клоаке redirect_uri.
				// Keycloak отображает страницу логина, выполняет авторизацию, делает редирект на redirect_uri
				// но БЕЗ ТОКЕНА (зато с заголовком code, по которому через доп запрос к клоаке можно получить jwt)
				// Проблема - отсутствие токена при редиректе из ck после ввода login/pass

				// Варианты решения:
				// 1. некий функционал на стороне keycloak, который поможет записать токен в заголовок redirect_uri
				//	плюсы:	* скорость. самый производительный вариант
				//			* не нужно городить каскад запросов в библиотеке krakend-jose, все необходимое в jose уже допилино
				//  минусы: * пока не понятно можно ли вообще такое реализовать
				//			* возможно нужно писать плагин/править используемую клоакой библиотеку на Java
				//
				// 2. допилить krakend-jose, логика такая:
				//	запрос на /krakend-protected
				//		-> срабатывает валидатор jwt (любая ошибка о токене)
				//		-> редирект на login page, пользователь авторизуется
				//		-> keycloak делает редирект на /krakend-protected без токена, но с заголовком code (Authorization Code в терминалогии OIDC) с помощью которого можно получить jwt
				//		(code=c081f6ca-ae87-40b6-8138-5afd4162d181.f109bb89-cd34-4374-b084-c3c1cf2c8a0b.1dc15d06-d8b9-4f0f-a042-727eaa6b98f7)
				//		-> т.к. мы без токена, то проваливаемся в тот же валидатор jwt, выполняем доп логику по условию наличия заголовка code:
				//		-> запрос на выгрузку токена по code
				// 		-> запрос на /krakend-protected с jwt
				// 		-> валидатор jwt пускает нас на защищенный ресурс
				return
			}

			claims := map[string]interface{}{}
			err = validator.Claims(c.Request, token, &claims)
			if err != nil {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client is invalid:", err.Error())
				}
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if rejecter.Reject(claims) {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client rejected")
				}
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if !aclCheck(scfg.RolesKey, claims, scfg.Roles) {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client does not have sufficient roles")
				}
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			if !scopesMatcher(scfg.ScopesKey, claims, scfg.Scopes) {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client does not have the required scopes")
				}
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			propagateHeaders(cfg, scfg.PropagateClaimsToHeader, claims, c, logger)

			paramExtractor(c, claims)

			handler(c)
		}
	}
}

func propagateHeaders(cfg *config.EndpointConfig, propagationCfg [][]string, claims map[string]interface{}, c *gin.Context, logger logging.Logger) {
	logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][PropagateHeaders]"
	if len(propagationCfg) > 0 {
		headersToPropagate, err := krakendjose.CalculateHeadersToPropagate(propagationCfg, claims)
		if err != nil {
			logger.Warning(logPrefix, err.Error())
		}
		for k, v := range headersToPropagate {
			// Set header value - replaces existing one
			c.Request.Header.Set(k, v)
		}
	}
}

var jwtParamsPattern = regexp.MustCompile(`{{\.JWT\.([^}]*)}}`)

func extractRequiredJWTClaims(cfg *config.EndpointConfig) func(*gin.Context, map[string]interface{}) {
	required := []string{}
	for _, backend := range cfg.Backend {
		for _, match := range jwtParamsPattern.FindAllStringSubmatch(backend.URLPattern, -1) {
			if len(match) < 2 {
				continue
			}
			required = append(required, match[1])
		}
	}
	if len(required) == 0 {
		return func(_ *gin.Context, _ map[string]interface{}) {}
	}

	return func(c *gin.Context, claims map[string]interface{}) {
		cl := krakendjose.Claims(claims)
		for _, param := range required {
			// TODO: check for nested claims
			v, ok := cl.Get(param)
			if !ok {
				continue
			}
			params := append(c.Params, gin.Param{Key: "JWT." + param, Value: v})
			c.Params = params
		}
	}
}

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(cookie.Value)
	}
}

func createJwtCookie(token string) http.Cookie {
	cookie := http.Cookie{}
	cookie.Name = "JWT"
	cookie.Expires = time.Now().UTC().Add(24 * 365 * time.Hour)
	cookie.HttpOnly = true
	cookie.Path = "/"
	cookie.Value = token
	cookie.Secure = false // использовать только при HTTPS-сессии, позднее поменять на true
	return cookie
}
