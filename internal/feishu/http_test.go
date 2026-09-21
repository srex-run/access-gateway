package feishu

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonHTTPResponse(value any) *http.Response {
	var body bytes.Buffer
	_ = json.NewEncoder(&body).Encode(value)
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body.Bytes())),
	}
}
