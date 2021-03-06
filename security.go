package httpexpect

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type SecurityConfig struct {
	SignatureEnabled bool
	EncryptEnabled   bool
	SigKV            string
	SigKey           string
	CtenKV           string
	CtenKey          string
}

type SecurityRequest struct {
	SigKV     string `json:"sgka" form:"sgka"`   // 签名的key的别名
	Cten      string `json:"stc" form:"stc"`     // 是否加密: v1不加密; v2加密
	CtenKV    string `json:"stcka" form:"stcka"` // 加密的key
	Content   string `json:"st" form:"st"`       // 内容
	Signature string `json:"sg" form:"sg"`       // 签名
	RawBody   []byte `json:"-"`
	RawQuery  string `json:"-"`
}

type Meta struct {
	Code         int    `json:"code"`
	ErrorType    string `json:"error_type,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type SecurityResponse struct {
	Meta     Meta   `json:"meta"`
	Content2 string `json:"st,omitempty"`
	Cten2    string `json:"stc,omitempty"`   // 是否加密: v1不加密; v2加密
	CtenKV2  string `json:"stcka,omitempty"` // 加密的key
}

func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		SignatureEnabled: false,
		EncryptEnabled:   false,
		SigKV:            "1",
		SigKey:           "1234567890abcdefghigklmnopqrstuv",
		CtenKV:           "1",
		CtenKey:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func (r *SecurityRequest) secRequestEncodeParams() string {
	v := url.Values{
		"st":    []string{r.Content},
		"sgka":  []string{r.SigKV},
		"stcka": []string{r.CtenKV},
		"sg":    []string{r.Signature},
		"stc":   []string{"v2"},
	}

	return v.Encode()
}

func secParams2JsonString(d *url.Values) (string, error) {
	datas := map[string]interface{}{}

	for k, v := range *d {
		datas[k] = v[0]
	}

	if result, err := json.Marshal(datas); err != nil {
		return "", err
	} else {
		return string(result), nil
	}
}

func secHmacSHA256String(k string, msg string) (string, error) {
	return secHmacSHA256Bytes(k, []byte(msg))
}

func secHmacSHA256Bytes(k string, msg []byte) (string, error) {
	mac := hmac.New(sha256.New, []byte(k))
	_, err := mac.Write(msg)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", mac.Sum(nil)), nil
}

func (c *Config) secGetDebugPrinter() *DebugPrinter {
	for _, print := range c.Printers {
		switch print.(type) {
		case DebugPrinter:
			v, ok := print.(DebugPrinter)
			if ok {
				return &v
			}
		}
	}
	return nil
}

func (r *Request) encryptRequest() error {
	printer := r.config.secGetDebugPrinter()

	req := SecurityRequest{}

	if r.config.SecurityConfig.EncryptEnabled {
		req.CtenKV = r.config.SecurityConfig.CtenKV
		req.Cten = "v2"

		if r.http.Method == http.MethodGet {
			if len(r.query) > 0 {
				//框架这里将 params 装成json string 然后encrypt
				paramsJson, err := secParams2JsonString(&r.query)
				if err != nil{
					r.config.Reporter.Errorf("Parse params to json with error(%s)", err.Error())
					return err
				}

				encData, err := EncryptECB(r.config.SecurityConfig.CtenKey, []byte(paramsJson))
				if err != nil {
					r.config.Reporter.Errorf("Request encrypt query signature with error(%s)", err.Error())
					return err
				}
				req.Content = encData

			}
		} else if r.http.Method == http.MethodPost {
			if r.http.ContentLength > 0 {
				buf := new(bytes.Buffer)

				_, err := buf.ReadFrom(r.http.Body)
				req.RawBody = buf.Bytes()

				if err != nil {
					r.config.Reporter.Errorf("Request sign body signature with error(%s)", err.Error())
					return err
				}

				encData, err := EncryptECB(r.config.SecurityConfig.CtenKey, req.RawBody)
				if err != nil {
					r.config.Reporter.Errorf("Request sign body signature with error(%s)", err.Error())
					return err
				}
				req.Content = encData
			}
		}

	}

	if r.config.SecurityConfig.SignatureEnabled {
		req.SigKV = r.config.SecurityConfig.SigKV

		if r.http.Method == http.MethodGet {
			if len(r.query) > 0 {
				signature, err := secHmacSHA256String(r.config.SecurityConfig.SigKey, req.Content)
				if err != nil {
					r.config.Reporter.Errorf("Request sign query signature with error(%s)", err.Error())
					return err
				}
				req.Signature = signature
			}
		} else if r.http.Method == http.MethodPost {
			if r.http.ContentLength > 0 {

				signature, err := secHmacSHA256String(r.config.SecurityConfig.SigKey, req.Content)
				if err != nil {
					r.config.Reporter.Errorf("Request sign body signature with error(%s)", err.Error())
					return err
				}
				req.Signature = signature
			}
		}

		if printer != nil {
			printer.logger.Logf("Security obj: %+v", req)
		}

		if r.http.Method == http.MethodPost {

			b, err := json.Marshal(req)
			if err != nil {
				r.config.Reporter.Errorf("Marshal security request with error(%s)", err.Error())
				return err
			}

			r.setBody(r.bodySetter, bytes.NewReader(b), len(b), true)
		} else if r.http.Method == http.MethodGet {
			params := req.secRequestEncodeParams()

			r.http.URL.RawQuery = params
		}

	}

	return nil
}

//
func (r *Response) decryptResponse() error {
	printer := r.config.secGetDebugPrinter()

	if r.config.SecurityConfig.EncryptEnabled {

		content := new(SecurityResponse)
		if err := json.Unmarshal(r.content, &content); err != nil {
			r.config.Reporter.Errorf("Unmarshal security response with error(%s)", err.Error())
			return err
		}

		resp := map[string]interface{}{
			"meta": content.Meta,
		}

		if len(content.Content2) > 0 {

			datas, err := DecryptECB(r.config.SecurityConfig.CtenKey, content.Content2)
			if err != nil {
				r.config.Reporter.Errorf("Decrypt security response with error(%s)", err.Error())
				return err
			}

			obj := new(interface{})
			if err := json.Unmarshal(datas, &obj); err != nil{
				r.config.Reporter.Errorf("Unmarshal decrypted data with error(%s)", err.Error())
				return err
			}

			resp["data"] = obj
		}

		result, err := json.Marshal(resp)
		if err != nil {
			r.config.Reporter.Errorf("Marshal security response with error(%s)", err.Error())
			return err
		}

		if printer != nil {
			printer.logger.Logf("Decrypted response: %s\n", result)
		}

		r.content = result
	}

	return nil
}

func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	if length == 0 {
		return make([]byte, 0)
	}
	unPadding := int(origData[length-1])
	if length < unPadding {
		return make([]byte, 0)
	}
	return origData[:(length - unPadding)]
}

// data: base64 encoded data
func DecryptECB(key string, data string) ([]byte, error) {

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	originData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(originData))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(originData); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], originData[bs:be])
	}

	return PKCS7UnPadding(decrypted), nil
}

func EncryptECB(key string, msg []byte) (string, error) {

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	msg = PKCS7Padding(msg, block.BlockSize())
	cryptData := make([]byte, len(msg))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(msg); bs, be = bs+size, be+size {
		block.Encrypt(cryptData[bs:be], msg[bs:be])
	}

	result := base64.StdEncoding.EncodeToString(cryptData)

	return result, nil
}
