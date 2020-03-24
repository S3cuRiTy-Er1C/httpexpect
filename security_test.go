package httpexpect

import (
	"encoding/json"
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