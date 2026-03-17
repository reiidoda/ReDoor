package network

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

var testNonceCounter uint64

func nextTestNonce() string {
	n := atomic.AddUint64(&testNonceCounter, 1)
	return fmt.Sprintf("nonce-%d", n)
}

func setRequestAuthHeaders(
	req *http.Request,
	key []byte,
	id string,
	receiver string,
	body []byte,
) {
	setRequestAuthHeadersWithValues(
		req,
		key,
		id,
		receiver,
		body,
		strconv.FormatInt(time.Now().Unix(), 10),
		nextTestNonce(),
	)
}

func setRequestAuthHeadersWithValues(
	req *http.Request,
	key []byte,
	id string,
	receiver string,
	body []byte,
	timestamp string,
	nonce string,
) {
	req.Header.Set("X-HMAC-Timestamp", timestamp)
	req.Header.Set("X-HMAC-Nonce", nonce)
	req.Header.Set("X-HMAC", computeRequestHMAC(key, id, receiver, body, timestamp, nonce))
}

func setScopedAuthHeaders(
	req *http.Request,
	cred ClientCredential,
	method string,
	path string,
	id string,
	receiver string,
	body []byte,
) {
	setScopedAuthHeadersWithValues(
		req,
		cred,
		method,
		path,
		id,
		receiver,
		body,
		strconv.FormatInt(time.Now().Unix(), 10),
		nextTestNonce(),
	)
}

func setScopedAuthHeadersWithValues(
	req *http.Request,
	cred ClientCredential,
	method string,
	path string,
	id string,
	receiver string,
	body []byte,
	timestamp string,
	nonce string,
) {
	req.Header.Set("X-Scoped-Token", cred.ScopedToken)
	req.Header.Set("X-Scoped-Token-Signature", cred.ScopedTokenSigB64)
	req.Header.Set("X-Scoped-Timestamp", timestamp)
	req.Header.Set("X-Scoped-Nonce", nonce)
	req.Header.Set("X-Scoped-Request-Signature", computeScopedRequestSignature(
		cred.Secret,
		cred.ClientID,
		method,
		path,
		id,
		receiver,
		body,
		timestamp,
		nonce,
	))
}
