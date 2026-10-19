package images

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The example from AWS's Signature Version 4 documentation, with its
// published example key.
func TestSignV4MatchesAWSExample(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	signV4(request, nil, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "iam", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := request.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization =\n%s\nwant\n%s", got, want)
	}
}

func TestECRRegion(t *testing.T) {
	for host, want := range map[string]string{
		"123456789012.dkr.ecr.eu-north-1.amazonaws.com":     "eu-north-1",
		"123456789012.dkr.ecr-fips.us-east-1.amazonaws.com": "us-east-1",
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn":  "cn-north-1",
	} {
		if region, ok := ECRRegion(host); !ok || region != want {
			t.Errorf("ECRRegion(%s) = %q, %v", host, region, ok)
		}
	}
	for _, host := range []string{"ghcr.io", "public.ecr.aws", "123.dkr.ecr.eu-north-1.amazonaws.com", "123456789012.dkr.ecr.eu-north-1.amazonaws.com.evil.example"} {
		if _, ok := ECRRegion(host); ok {
			t.Errorf("%s taken for ECR", host)
		}
	}
}

func TestECRToken(t *testing.T) {
	const registry = "123456789012.dkr.ecr.eu-north-1.amazonaws.com"
	expires := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/20261019/eu-north-1/ecr/aws4_request, ") {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"__type": "UnrecognizedClientException", "message": "The security token included in the request is invalid."})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"authorizationData": []map[string]any{{
			"authorizationToken": base64.StdEncoding.EncodeToString([]byte("AWS:short-lived")),
			"expiresAt":          float64(expires.Unix()),
		}}})
	}))
	defer server.Close()
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

	credentials, until, err := ECRToken(context.Background(), server.Client(), registry, server.URL, "AKIDTEST", "secret", now)
	if err != nil || credentials.Username != "AWS" || credentials.Password != "short-lived" || !until.Equal(expires) {
		t.Fatalf("ECRToken = %+v until %s, %v", credentials, until, err)
	}
	_, _, err = ECRToken(context.Background(), server.Client(), registry, server.URL, "WRONG", "secret", now)
	if !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), "UnrecognizedClientException") {
		t.Fatalf("a wrong key: %v", err)
	}
	if _, _, err := ECRToken(context.Background(), server.Client(), "ghcr.io", server.URL, "AKIDTEST", "secret", now); err == nil {
		t.Fatal("a token was asked for a registry that isn't ECR")
	}
}
