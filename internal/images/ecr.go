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
	answer, err := ecrCall(ctx, client, registry, endpoint, region, keyID, secret, "GetAuthorizationToken", []byte("{}"), now)
	if err != nil {
		return Credentials{}, time.Time{}, err
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

// ecrCall calls one action of the ECR API with an AWS access key, and
// returns its answer, or AWS's reason for refusing.
func ecrCall(ctx context.Context, client *http.Client, registry, endpoint, region, keyID, secret, action string, body []byte, now time.Time) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921."+action)
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	signV4(request, body, keyID, secret, region, "ecr", now)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call ECR's %s for %s: %w", action, registry, err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 16<<20))
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
		return nil, fmt.Errorf("%s: %w (AWS answered %s to %s)", registry, ErrUnauthorized, reason, action)
	}
	return answer, nil
}

// ECRAPI lists repositories and images with the ECR API, which, unlike the
// registry API, also says when each image was pushed. Its key needs
// ecr:DescribeRepositories and ecr:DescribeImages.
type ECRAPI struct {
	Client             *http.Client
	Registry, Endpoint string
	KeyID, Secret      string
}

func (api ECRAPI) call(ctx context.Context, action string, request any, into any) error {
	region, ok := ECRRegion(api.Registry)
	if !ok {
		return fmt.Errorf("%s is not an Amazon ECR registry host", api.Registry)
	}
	endpoint := api.Endpoint
	if endpoint == "" {
		endpoint = "https://api.ecr." + region + ".amazonaws.com/"
		if strings.HasSuffix(api.Registry, ".cn") {
			endpoint = "https://api.ecr." + region + ".amazonaws.com.cn/"
		}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	answer, err := ecrCall(ctx, api.Client, api.Registry, endpoint, region, api.KeyID, api.Secret, action, body, time.Now())
	if err != nil {
		return err
	}
	if err := json.Unmarshal(answer, into); err != nil {
		return fmt.Errorf("%s: unreadable answer to %s: %w", api.Registry, action, err)
	}
	return nil
}

// account is the AWS account an ECR registry host belongs to.
func (api ECRAPI) account() string {
	account, _, _ := strings.Cut(api.Registry, ".")
	return account
}

// Repositories lists the registry's repositories.
func (api ECRAPI) Repositories(ctx context.Context) ([]string, error) {
	var names []string
	token := ""
	for len(names) < maxListed {
		request := map[string]any{"registryId": api.account(), "maxResults": 1000}
		if token != "" {
			request["nextToken"] = token
		}
		var page struct {
			Repositories []struct {
				Name string `json:"repositoryName"`
			} `json:"repositories"`
			NextToken string `json:"nextToken"`
		}
		if err := api.call(ctx, "DescribeRepositories", request, &page); err != nil {
			return nil, err
		}
		for _, repository := range page.Repositories {
			names = append(names, repository.Name)
		}
		if token = page.NextToken; token == "" {
			break
		}
	}
	sort.Strings(names)
	return names, nil
}

// Tags lists a repository's tagged images, with their digests and push
// times.
func (api ECRAPI) Tags(ctx context.Context, repository string) ([]TagInfo, error) {
	var tags []TagInfo
	token := ""
	for len(tags) < maxListed {
		request := map[string]any{"registryId": api.account(), "repositoryName": repository, "maxResults": 1000, "filter": map[string]string{"tagStatus": "TAGGED"}}
		if token != "" {
			request["nextToken"] = token
		}
		var page struct {
			Images []struct {
				Digest   string   `json:"imageDigest"`
				Tags     []string `json:"imageTags"`
				PushedAt float64  `json:"imagePushedAt"`
			} `json:"imageDetails"`
			NextToken string `json:"nextToken"`
		}
		if err := api.call(ctx, "DescribeImages", request, &page); err != nil {
			return nil, err
		}
		for _, image := range page.Images {
			pushed := time.Unix(int64(image.PushedAt), 0).UTC()
			for _, tag := range image.Tags {
				tags = append(tags, TagInfo{Tag: tag, Digest: image.Digest, PushedAt: pushed})
			}
		}
		if token = page.NextToken; token == "" {
			break
		}
	}
	return tags, nil
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
