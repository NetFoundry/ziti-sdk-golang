/*
	Copyright 2019 NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package enroll

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/openziti/edge-api/rest_client_api_client"
	"github.com/openziti/edge-api/rest_client_api_client/well_known"
	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Jeffail/gabs"
	"github.com/fullsailor/pkcs7"
	"github.com/golang-jwt/jwt/v5"
	"github.com/michaelquigley/pfxlog"
	nfpem "github.com/openziti/foundation/v2/pem"
	nfx509 "github.com/openziti/foundation/v2/x509"
	"github.com/openziti/identity"
	"github.com/openziti/identity/certtools"
	"github.com/pkg/errors"
)

type EnrollmentFlags struct {
	Token         *ziti.EnrollmentClaims
	JwtToken      *jwt.Token
	JwtString     string
	CertFile      string
	KeyFile       string
	KeyAlg        ziti.KeyAlgVar
	IDName        string
	AdditionalCAs string
	Username      string
	Password      string
	Verbose       bool
}

func (enFlags *EnrollmentFlags) GetCertPool() (*x509.CertPool, []*x509.Certificate) {
	pool := x509.NewCertPool()
	var certs []*x509.Certificate

	if strings.TrimSpace(enFlags.AdditionalCAs) != "" {
		pfxlog.Logger().Debug("adding certificates from the provided ca override file")
		caPEMs, _ := os.ReadFile(enFlags.AdditionalCAs)
		for _, xcert := range nfpem.PemStringToCertificates(string(caPEMs)) {
			certs = append(certs, xcert)
			pool.AddCert(xcert)
		}
	}

	return pool, certs
}

func ParseToken(tokenStr string) (*ziti.EnrollmentClaims, *jwt.Token, error) {
	parser := jwt.NewParser()
	enrollmentClaims := &ziti.EnrollmentClaims{}
	tokenStr = strings.TrimSpace(tokenStr)
	jwtToken, err := parser.ParseWithClaims(tokenStr, enrollmentClaims, ValidateToken)

	if err != nil {
		return nil, nil, err
	}

	return enrollmentClaims, jwtToken, nil
}

func ValidateToken(token *jwt.Token) (interface{}, error) {
	if token == nil {
		return nil, errors.New("could not validate token, token is nil")
	}

	claims, ok := token.Claims.(*ziti.EnrollmentClaims)

	if !ok {
		return nil, errors.New("could not validate token, token is not EnrollmentClaims")
	}

	if claims == nil {
		return nil, errors.New("could not validate token, EnrollmentClaims are nil")
	}

	if claims.Issuer == "" {
		return nil, errors.New("could not validate token, issuer is empty")
	}

	_, err := url.Parse(claims.Issuer)

	if err != nil {
		return nil, errors.Errorf("could not validate token, issuer [%s] is not a valid url ", claims.Issuer)
	}

	cert, err := FetchServerCert(claims.Issuer)

	claims.SignatureCert = cert

	if err != nil || cert == nil {
		return nil, errors.Errorf("could not retrieve token URL certificate: %s", err)
	}

	return cert.PublicKey, nil
}

func EnrollUpdb(enFlags EnrollmentFlags) error {
	caPool, allowedCerts := enFlags.GetCertPool()
	ztApiRoot := enFlags.Token.Issuer

	if err := enrollUpdb(enFlags.Username, enFlags.Password, enFlags.Token, caPool); err != nil {
		pfxlog.Logger().Debug("fetching certificates from server")
		rootCaPool := x509.NewCertPool()
		rootCaPool.AddCert(enFlags.Token.SignatureCert)

		for _, xcert := range FetchCertificates(ztApiRoot, rootCaPool) {
			allowedCerts = append(allowedCerts, xcert)
			caPool.AddCert(xcert)
		}

		if err := enrollUpdb(enFlags.Username, enFlags.Password, enFlags.Token, caPool); err != nil {
			return fmt.Errorf("unable to enroll after fetching server certs: %v", err)
		} else {
			return nil
		}
	}

	return nil
}

func Enroll(enFlags EnrollmentFlags) (*ziti.Config, error) {
	var key crypto.PrivateKey
	var err error

	cfg := &ziti.Config{
		ZtAPI: edge_apis.ClientUrl(enFlags.Token.Issuer),
	}

	if strings.TrimSpace(enFlags.KeyFile) != "" {
		stat, err := os.Stat(enFlags.KeyFile)

		if stat != nil && !os.IsNotExist(err) {
			if stat.IsDir() {
				return nil, errors.Errorf("specified key is a directory (%s)", enFlags.KeyFile)
			}

			if absPath, fileErr := filepath.Abs(enFlags.KeyFile); fileErr != nil {
				return nil, fileErr
			} else {
				cfg.ID.Key = "file://" + absPath
			}

		} else {
			cfg.ID.Key = enFlags.KeyFile
			pfxlog.Logger().Infof("using engine : %s\n", strings.Split(enFlags.KeyFile, ":")[0])
		}
	} else {
		var asnBytes []byte
		var keyPem []byte
		if enFlags.KeyAlg.EC() {
			key, err = generateECKey()
			asnBytes, _ := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
			keyPem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: asnBytes})
		} else if enFlags.KeyAlg.RSA() {
			key, err = generateRSAKey()
			asnBytes = x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
			keyPem = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: asnBytes})
		} else {
			panic(fmt.Sprintf("invalid KeyAlg specified: %s", enFlags.KeyAlg.Get()))
		}
		cfg.ID.Key = "pem:" + string(keyPem)
		if err != nil {
			return nil, err
		}
	}

	if enFlags.CertFile != "" {
		enFlags.CertFile, _ = filepath.Abs(enFlags.CertFile)
		cfg.ID.Cert = "file://" + enFlags.CertFile
	}

	caPool, allowedCerts := enFlags.GetCertPool()

	//fetch so CA bundles
	pfxlog.Logger().Debug("fetching certificates from server")
	serverOnlyCaPool := x509.NewCertPool()
	serverOnlyCaPool.AddCert(enFlags.Token.SignatureCert)

	controllerCas := FetchCertificates(cfg.ZtAPI, serverOnlyCaPool)

	if len(controllerCas) == 0 {
		return nil, errors.New("expected 1 or more CAs from controller, got 0")
	}

	for _, cert := range controllerCas {
		allowedCerts = append(allowedCerts, cert)
		caPool.AddCert(cert)
	}

	var enrollErr error
	switch enFlags.Token.EnrollmentMethod {
	case "ott":
		enrollErr = enrollOTT(enFlags.Token, cfg, caPool)
	case "ottca":
		enrollErr = enrollCA(enFlags.Token, cfg, caPool)
	case "ca":
		enrollErr = enrollCAAuto(enFlags, cfg, caPool)
	default:
		enrollErr = errors.Errorf("enrollment method '%s' is not supported", enFlags.Token.EnrollmentMethod)
	}

	if enrollErr != nil {
		return nil, enrollErr
	}

	if len(allowedCerts) > 0 {
		var buf bytes.Buffer

		err := nfx509.MarshalToPem(allowedCerts, &buf)

		if err != nil {
			return nil, err
		}

		cfg.ID.CA = "pem:" + buf.String()
	}

	cfg.Credentials = edge_apis.NewIdentityCredentialsFromConfig(cfg.ID)

	return cfg, nil
}

func generateECKey() (crypto.PrivateKey, error) {
	p384 := elliptic.P384()
	pfxlog.Logger().Infof("generating %s EC key", p384.Params().Name)
	return ecdsa.GenerateKey(p384, rand.Reader)
}

func generateRSAKey() (crypto.PrivateKey, error) {
	bitSize := 4096
	pfxlog.Logger().Infof("generating %d bit RSA key", bitSize)
	return rsa.GenerateKey(rand.Reader, bitSize)
}

func useSystemCasIfEmpty(caPool *x509.CertPool) *x509.CertPool {
	if len(caPool.Subjects()) < 1 { //nolint:staticcheck
		pfxlog.Logger().Debugf("no cas provided in caPool. using system provided cas")
		//this means that there were no ca's in the jwt and none fetched and added... fallback to using
		//the system defined ca pool in this case
		return nil
	} else {
		return caPool
	}
}

func enrollUpdb(username, password string, token *ziti.EnrollmentClaims, caPool *x509.CertPool) error {
	caPool = useSystemCasIfEmpty(caPool)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}

	body := gabs.New()
	_, _ = body.Set(password, "password")

	if username != "" {
		_, _ = body.Set(username, "username")
	}

	enrollmentUrls := token.EnrolmentUrls()

	var resp *http.Response
	var err error
	for _, enrollmentUrl := range enrollmentUrls {
		resp, err = client.Post(enrollmentUrl, "application/json", bytes.NewBuffer(body.EncodeJSON()))

		if err != nil {
			continue
		}

	}

	if err != nil {
		return err
	}

	if resp == nil {
		return errors.New("enrollment returned empty response")
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)

	if respContainer, err := gabs.ParseJSON(respBody); err == nil {
		code := respContainer.Path("error.code").Data().(string)
		message := respContainer.Path("error.message").Data().(string)
		return errors.Errorf("enroll error: %s: %s: %s", resp.Status, code, message)
	} else {
		return errors.Errorf("enroll error: %s: %s", resp.Status, body)
	}
}

func enrollOTT(token *ziti.EnrollmentClaims, cfg *ziti.Config, caPool *x509.CertPool) error {
	pk, err := identity.LoadKey(cfg.ID.Key)
	if err != nil {
		return errors.Errorf("failed to load private key '%s': %s", cfg.ID.Key, err.Error())
	}

	request, err := certtools.NewCertRequest(map[string]string{
		"C": "US", "O": "NetFoundry", "CN": token.Subject,
	}, nil)
	if err != nil {
		return err
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, request, pk)

	if err != nil {
		return err
	}

	csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	caPool = useSystemCasIfEmpty(caPool)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}

	enrollmentUrls := token.EnrolmentUrls()

	var resp *http.Response
	for _, enrollmentUrl := range enrollmentUrls {
		resp, err = client.Post(enrollmentUrl, "application/x-pem-file", bytes.NewReader(csrPem))

		if err != nil {
			continue
		}

	}

	if err != nil {
		return err
	}

	if resp == nil {
		return errors.New("enrollment returned empty response")
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return errors.Errorf("enroll error: %s: could not read body: %s", resp.Status, body)
	}

	if resp.StatusCode == http.StatusOK {
		contentTypes := resp.Header.Values("content-type")

		if len(contentTypes) == 1 {
			if contentTypes[0] == "application/json" {
				container, err := gabs.ParseJSON(body)
				if err != nil {
					return fmt.Errorf("could not parse json enrollment response: %v", err)
				}
				certPem, ok := container.Path("data.cert").Data().(string)

				if !ok {
					return errors.New("could not find data.cert in enrollment response")
				}

				cfg.ID.Cert = "pem:" + certPem
				return nil
			} else {
				cfg.ID.Cert = "pem:" + string(body)
			}
		} else {
			pfxlog.Logger().Warnf("more than one content-type detected. Using response as pem. content-types: %s", strings.Join(contentTypes, ", "))
			cfg.ID.Cert = "pem:" + string(body)
		}

		return nil
	}

	jsonBody, err := gabs.ParseJSON(body)

	if err != nil {
		return errors.Errorf("enroll error: %s: could not parse body: %s", resp.Status, body)
	}

	if jsonBody.Exists("error", "message") {
		message := jsonBody.Search("error", "message").Data().(string)
		code := jsonBody.Search("error", "code").Data().(string)

		//todo: remove causeMessage support when removed from API
		cause := ""
		if jsonBody.Exists("error", "cause", "message") {
			cause = jsonBody.Search("error", "cause", "message").Data().(string)
		}

		if cause == "" && jsonBody.Exists("error", "causeMessage") {
			cause = jsonBody.Search("error", "causeMessage").Data().(string)
		}

		return errors.Errorf("enroll error: %s - code: %s - message: %s - cause: %s", resp.Status, code, message, cause)
	}

	return errors.Errorf("enroll error: %s: unrecognized response: %s", resp.Status, body)
}

func enrollCA(token *ziti.EnrollmentClaims, cfg *ziti.Config, caPool *x509.CertPool) error {

	if id, err := identity.LoadIdentity(cfg.ID); err != nil {
		return err
	} else {
		clientCert := id.Cert()

		caPool = useSystemCasIfEmpty(caPool)
		client := http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caPool,
					Certificates: []tls.Certificate{*clientCert},
				},
				Proxy: http.ProxyFromEnvironment,
			},
		}

		enrollmentUrls := token.EnrolmentUrls()

		var resp *http.Response
		for _, enrollmentUrl := range enrollmentUrls {
			resp, err = client.Post(enrollmentUrl, "text/plain", bytes.NewReader([]byte{}))

			if err != nil {
				continue
			}

		}

		if err != nil {
			return err
		}

		if resp == nil {
			return errors.New("enrollment returned empty response")
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusConflict {
				return errors.Errorf("the provided identity has already been enrolled")
			} else {
				return errors.Errorf("enroll error: %s", resp.Status)
			}
		}
		return nil
	}
}

type autoEnrollInput struct {
	Name string `json:"name"`
}

func enrollCAAuto(enFlags EnrollmentFlags, cfg *ziti.Config, caPool *x509.CertPool) error {
	if id, err := identity.LoadIdentity(cfg.ID); err != nil {
		return err
	} else {
		clientCert := id.Cert()

		caPool = useSystemCasIfEmpty(caPool)
		client := http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caPool,
					Certificates: []tls.Certificate{*clientCert},
				},
				Proxy: http.ProxyFromEnvironment,
			},
		}

		var postBody []byte

		if strings.TrimSpace(enFlags.IDName) != "" {
			user := autoEnrollInput{
				Name: strings.TrimSpace(enFlags.IDName),
			}
			pb, merr := json.Marshal(user)
			if merr != nil {
				pfxlog.Logger().Warnf("problem converting name to json. Using the default name: %s", merr)
			}
			postBody = pb
		}

		enrollmentUrls := enFlags.Token.EnrolmentUrls()

		var resp *http.Response
		for _, enrollmentUrl := range enrollmentUrls {
			resp, err = client.Post(enrollmentUrl, "application/json", bytes.NewReader(postBody))

			if err != nil {
				continue
			}

		}

		if err != nil {
			return err
		}

		if resp == nil {
			return errors.New("enrollment returned empty response")
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusConflict {
				return errors.New("the provided identity has already been enrolled")
			} else {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return errors.Errorf("enroll error: %s", resp.Status)
				}

				if respContainer, err := gabs.ParseJSON(body); err == nil {
					code := respContainer.Path("error.code").Data().(string)
					message := respContainer.Path("error.message").Data().(string)
					return errors.Errorf("enroll error: %s: %s: %s", resp.Status, code, message)
				} else {
					return errors.Errorf("enroll error: %s: %s", resp.Status, body)
				}
			}
		}
		return nil
	}
}

func FetchServerCert(urlRoot string) (*x509.Certificate, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(urlRoot)

	if err != nil {
		return nil, errors.Errorf("could not contact remote server [%s]: %s", urlRoot, err)
	}

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, errors.New("peer certificate information is missing")
	}

	return resp.TLS.PeerCertificates[0], nil
}

// FetchCertificates will access the server insecurely to pull down the latest CA to be used to communicate with the
// server adding certificates to the provided pool
func FetchCertificates(urlRoot string, rootCaPool *x509.CertPool) []*x509.Certificate {
	ctrlUrl, err := url.Parse(urlRoot)

	if err != nil {
		pfxlog.Logger().Errorf("could not parse url root: %s", err)
		return nil //@todo figure out what the impact is here of returning an error on other callers
	}

	path := rest_client_api_client.DefaultBasePath

	if ctrlUrl.Path != "" && ctrlUrl.Path != "/" {
		path = ctrlUrl.Path
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCaPool},
			Proxy:           http.ProxyFromEnvironment,
		},
	}

	clientRuntime := httptransport.NewWithClient(ctrlUrl.Host, path, rest_client_api_client.DefaultSchemes, httpClient)
	clientRuntime.Consumers["application/pkcs7-mime"] = runtime.ConsumerFunc(func(reader io.Reader, i interface{}) error {
		out := i.(*string)

		buff, err := io.ReadAll(reader)

		if err != nil {
			return err
		}

		*out = string(buff)

		return nil
	})
	client := rest_client_api_client.New(clientRuntime, nil)

	resp, err := client.WellKnown.ListWellKnownCas(well_known.NewListWellKnownCasParams())

	if err != nil {
		return nil
	}

	if resp.Payload == "" {
		pfxlog.Logger().Debug("no certificates returned from well know ca store")
		return nil
	}

	pkcs7Certs, _ := base64.StdEncoding.DecodeString(string(resp.Payload))
	if pkcs7Certs != nil {
		certs, parseErr := pkcs7.Parse(pkcs7Certs)
		if parseErr != nil {
			pfxlog.Logger().Warnf("could not parse certificates. no certificates added from %s", urlRoot)
			return nil
		}
		return certs.Certificates
	}

	return nil
}
