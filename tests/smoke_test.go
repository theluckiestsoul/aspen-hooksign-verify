package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hooksign/hooksign"
)

const (
	AdminKey = "admin-key-001"
	AliceKey = "user-key-001"
	BobKey   = "user-key-002"
	CarolKey = "user-key-003"

	AlicePartner = "stripe-mock"
	AliceSecret  = "whsec_alpha_a1b2c3d4e5f6"
	BobPartner   = "github-mock"
	BobSecret    = "whsec_beta_b2c3d4e5f6a1"
	CarolPartner = "slack-mock"
	CarolSecret  = "whsec_gamma_c3d4e5f6a1b2"
)

func NewTestServer() *httptest.Server {
	return httptest.NewServer(hooksign.NewApp())
}

func Sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func DoRequest(t *testing.T, srv *httptest.Server, method, path, apiKey, body string, extraHeaders map[string]string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("executing request: %v", err)
	}
	return resp
}

func TestSmoke_PartnerReadsOwnPartner(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	resp := DoRequest(t, srv, "GET", "/partners/"+AlicePartner, AliceKey, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var p map[string]any
	json.NewDecoder(resp.Body).Decode(&p)
	if p["name"] != AlicePartner {
		t.Fatalf("unexpected name: %v", p["name"])
	}
}

func TestSmoke_AdminListsAllPartners(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	resp := DoRequest(t, srv, "GET", "/partners", AdminKey, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var list []map[string]any
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) < 3 {
		t.Fatalf("expected at least 3 partners, got %d", len(list))
	}
}

func TestSmoke_NonOwnerCannotReadOthersPartner(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	resp := DoRequest(t, srv, "GET", "/partners/"+BobPartner, AliceKey, "", nil)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestSmoke_AdminCreatesPartner(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	body := `{"name":"new-partner","owner":"user-001","secret":"whsec_new_secret_value"}`
	resp := DoRequest(t, srv, "POST", "/partners", AdminKey, body, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestSmoke_NonAdminCannotCreatePartner(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	body := `{"name":"sneaky","owner":"user-001","secret":"whsec_nope"}`
	resp := DoRequest(t, srv, "POST", "/partners", AliceKey, body, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestSmoke_AdminDeletesPartner(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	create := `{"name":"temp-partner","owner":"user-001","secret":"whsec_temp_secret"}`
	resp := DoRequest(t, srv, "POST", "/partners", AdminKey, create, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("expected create 201, got %d", resp.StatusCode)
	}

	resp = DoRequest(t, srv, "DELETE", "/partners/temp-partner", AdminKey, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected delete 200, got %d", resp.StatusCode)
	}
}

func TestSmoke_WellSignedWebhookAccepted(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	body := `{"event":"payment.succeeded","amount":1200}`
	ts := time.Now().Unix()
	sig := Sign(AliceSecret, ts, []byte(body))

	resp := DoRequest(t, srv, "POST", "/webhooks/"+AlicePartner, "", body, map[string]string{
		"X-Delivery-ID":        "smoke-delivery-001",
		"X-Webhook-Timestamp":  fmt.Sprintf("%d", ts),
		"X-Signature":          sig,
		"X-Signature-Alg":      "sha256",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["status"] != "accepted" {
		t.Fatalf("expected status=accepted, got %v", out["status"])
	}
}

func TestSmoke_MismatchedSignatureRejected(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	body := `{"event":"payment.succeeded"}`
	ts := time.Now().Unix()
	wrong := Sign("not-the-real-secret-xxx", ts, []byte(body))

	resp := DoRequest(t, srv, "POST", "/webhooks/"+AlicePartner, "", body, map[string]string{
		"X-Delivery-ID":        "smoke-delivery-002",
		"X-Webhook-Timestamp":  fmt.Sprintf("%d", ts),
		"X-Signature":          wrong,
		"X-Signature-Alg":      "sha256",
	})
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSmoke_MissingDeliveryIDRejected(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	body := `{"event":"x"}`
	ts := time.Now().Unix()
	sig := Sign(AliceSecret, ts, []byte(body))

	resp := DoRequest(t, srv, "POST", "/webhooks/"+AlicePartner, "", body, map[string]string{
		"X-Webhook-Timestamp": fmt.Sprintf("%d", ts),
		"X-Signature":         sig,
	})
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSmoke_AdminListsEvents(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	body := `{"event":"audit"}`
	ts := time.Now().Unix()
	sig := Sign(AliceSecret, ts, []byte(body))
	resp := DoRequest(t, srv, "POST", "/webhooks/"+AlicePartner, "", body, map[string]string{
		"X-Delivery-ID":       "smoke-delivery-003",
		"X-Webhook-Timestamp": fmt.Sprintf("%d", ts),
		"X-Signature":         sig,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("expected receive 200, got %d", resp.StatusCode)
	}

	resp = DoRequest(t, srv, "GET", "/events", AdminKey, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected list 200, got %d", resp.StatusCode)
	}
}

func TestSmoke_MissingAPIKey(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/partners", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSmoke_InvalidAPIKey(t *testing.T) {
	srv := NewTestServer()
	defer srv.Close()

	resp := DoRequest(t, srv, "GET", "/partners", "bad-key-xxx", "", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}
