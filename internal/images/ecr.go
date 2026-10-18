package images

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
)

// Amazon ECR doesn't take a fixed password: its registry password is a token
// that lasts 12 hours, from the ECR API's GetAuthorizationToken, called with
// an AWS access key. DeaconGuard keeps the access key and gets a token when
// it needs one.

var ecrHost = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$`)

// ECRRegion is the AWS region of an ECR registry host, such as
// 123456789012.dkr.ecr.eu-north-1.amazonaws.com; ok is false for any other host.
func ECRRegion(registry string) (region string, ok bool) {
	match := ecrHost.FindStringSubmatch(registry)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// ECRToken exchanges an AWS access key for a registry login, and says when it
// expires. endpoint is the ECR API's address; "" is the region's own.
func ECRToken(ctx context.Context, client *http.Client, registry, endpoint, keyID, secret string, now time.Time) (Credentials, time.Time, error) {
	region, ok := ECRRegion(registry)
	if !ok {
		return Credentials{}, time.Time{}, fmt.Errorf("%s is not an Amazon ECR registry host", registry)
	}
	if endpoint == "" {
		endpoint = "https://api.ecr." + region + ".amazonaws.com/"
		if strings.HasSuffix(registry, ".cn") {
			endpoint = "https://api.ecr." + region + ".amazonaws.com.cn/"
		}
	}
	body := []byte("{}")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Credentials{}, time.Time{}, err
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken")
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	signV4(request, body, keyID, secret, region, "ecr", now)
	response, err := client.Do(request)
	if err != nil {
		return Credentials{}, time.Time{}, fmt.Errorf("get an ECR login for %s: %w", registry, err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
		}
		json.Unmarshal(answer, &failure)
		reason := strings.TrimSpace(failure.Type + ": " + failure.Message)
		if failure.Type == "" {
			reason = response.Status
		}
		return Credentials{}, time.Time{}, fmt.Errorf("%s: %w (AWS answered %s)", registry, ErrUnauthorized, reason)
	}
	var result struct {
		AuthorizationData []struct {
			AuthorizationToken string  `json:"authorizationToken"`
			ExpiresAt          float64 `json:"expiresAt"`
		} `json:"authorizationData"`
	}
	if err := json.Unmarshal(answer, &result); err != nil || len(result.AuthorizationData) == 0 {
		return Credentials{}, time.Time{}, fmt.Errorf("get an ECR login for %s: unexpected answer", registry)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.AuthorizationData[0].AuthorizationToken)
	user, password, found := strings.Cut(string(decoded), ":")
	if err != nil || !found {
		return Credentials{}, time.Time{}, fmt.Errorf("get an ECR login for %s: unreadable token", registry)
	}
	expires := time.Unix(int64(result.AuthorizationData[0].ExpiresAt), 0)
	if result.AuthorizationData[0].ExpiresAt == 0 {
		expires = now.Add(12 * time.Hour)
	}
	return Credentials{Username: user, Password: password}, expires, nil
}

// signV4 signs a request with AWS Signature Version 4.
func signV4(request *http.Request, body []byte, keyID, secret, region, service string, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	request.Header.Set("X-Amz-Date", stamp)
	payload := sha256.Sum256(body)

	names := []string{"host"}
	values := map[string]string{"host": request.URL.Host}
	for name, value := range request.Header {
		lower := strings.ToLower(name)
		if lower == "user-agent" || lower == "authorization" {
			continue
		}
		names = append(names, lower)
		values[lower] = strings.Join(strings.Fields(strings.Join(value, ",")), " ")
	}
	sort.Strings(names)
	var headers strings.Builder
	for _, name := range names {
		headers.WriteString(name + ":" + values[name] + "\n")
	}
	signed := strings.Join(names, ";")
	path := request.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{request.Method, path, canonicalQuery(request.URL.Query()), headers.String(), signed, hex.EncodeToString(payload[:])}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(digest[:])

	key := hmacSHA256([]byte("AWS4"+secret), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+keyID+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
}

func canonicalQuery(query map[string][]string) string {
	var parts []string
	for name, values := range query {
		for _, value := range values {
			parts = append(parts, awsEscape(name)+"="+awsEscape(value))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// awsEscape percent-encodes everything but unreserved characters.
func awsEscape(value string) string {
	var result strings.Builder
	for _, b := range []byte(value) {
		if ('A' <= b && b <= 'Z') || ('a' <= b && b <= 'z') || ('0' <= b && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~' {
			result.WriteByte(b)
		} else {
			fmt.Fprintf(&result, "%%%02X", b)
		}
	}
	return result.String()
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
