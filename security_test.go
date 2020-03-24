package httpexpect

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestEncryptECB(t *testing.T) {
	data := map[string]interface{}{
		"abc": "def",
		"hij": "klm",
	}

	datas, err := json.Marshal(data)
	t.Log(datas, err)
}

func TestParams2JsonString(t *testing.T){
	r := SecurityRequest{
		SigKV:     "123",
		Cten:      "33",
		CtenKV:    "444",
		Content:   "fffffffaaaaaverylongabc",
		Signature: "sssss",
	}
	t.Log(r.secRequestEncodeParams())

	v := url.Values{
		"st": []string{r.Content},
		"sgka": []string{r.SigKV},
		"stcka": []string{r.CtenKV},
		"sg": []string{r.Signature},
		"stc": []string{"v2"},
	}

	datas, err := json.Marshal(v)
	t.Log(datas, err)
	t.Log(string(datas))

	j := new(interface{})
	err = json.Unmarshal(datas, &j)
	t.Log(j, err)

	t.Log(secParams2JsonString(&v))
}