// Package kube reads a Kubernetes cluster through its API, read-only: it
// only lists and gets objects, and checks them. It speaks the API's REST
// protocol itself, with a kubeconfig (client certificates, tokens, or an
// exec plugin such as the EKS, GKE and AKS logins) or a pod's service
// account.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"deaconguard/internal/buildinfo"
)

// Client is a read-only Kubernetes API client.
type Client struct {
	// Server is the API server's address; Name says which cluster it is,
	// the kubeconfig context or "in-cluster".
	Server string
	Name   string
	http   *http.Client
	// token returns the bearer token, renewing an exec plugin's when it
	// expires; nil with client certificates.
	token func(context.Context) (string, error)
}

const serviceAccount = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubeconfig is the part of a kubeconfig file the client reads.
type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Contexts       []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			TLSServerName            string `yaml:"tls-server-name"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKey             string `yaml:"client-key"`
			ClientKeyData         string `yaml:"client-key-data"`
			Username              string `yaml:"username"`
			Password              string `yaml:"password"`
			Exec                  *struct {
				APIVersion string   `yaml:"apiVersion"`
				Command    string   `yaml:"command"`
				Args       []string `yaml:"args"`
				Env        []struct {
					Name  string `yaml:"name"`
					Value string `yaml:"value"`
				} `yaml:"env"`
			} `yaml:"exec"`
			AuthProvider any `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// Connect makes a client: from the kubeconfig file (KUBECONFIG, or
// ~/.kube/config) and context named, or from the pod's service account when
// running in a cluster without a kubeconfig.
func Connect(kubeconfigPath, contextName string) (*Client, error) {
	if kubeconfigPath == "" {
		if env := os.Getenv("KUBECONFIG"); env != "" {
			kubeconfigPath = strings.Split(env, string(os.PathListSeparator))[0]
		} else if home, err := os.UserHomeDir(); err == nil {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}
	if _, err := os.Stat(kubeconfigPath); err != nil || kubeconfigPath == "" {
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && contextName == "" {
			return inCluster()
		}
		return nil, fmt.Errorf("no kubeconfig at %s: give one with --kubeconfig, or run in a cluster", kubeconfigPath)
	}
	return fromKubeconfig(kubeconfigPath, contextName)
}

func inCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	ca, err := os.ReadFile(filepath.Join(serviceAccount, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read the service account's CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("the service account's CA is not a PEM certificate")
	}
	server := "https://" + strings.Trim(host, "[]")
	if strings.Contains(host, ":") {
		server = "https://[" + strings.Trim(host, "[]") + "]"
	}
	client := &Client{Server: server + ":" + port, Name: "in-cluster",
		http: &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}
	// The kubelet rotates the projected token; read it each time.
	client.token = func(context.Context) (string, error) {
		data, err := os.ReadFile(filepath.Join(serviceAccount, "token"))
		return strings.TrimSpace(string(data)), err
	}
	return client, nil
}

// fileOrData reads a kubeconfig field that is either inline base64 data or
// a path, relative to the kubeconfig's folder.
func fileOrData(data, path, base string) ([]byte, error) {
	if data != "" {
		return base64.StdEncoding.DecodeString(data)
	}
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	return os.ReadFile(path)
}

func fromKubeconfig(path, contextName string) (*Client, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config kubeconfig
	if err := yaml.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if contextName == "" {
		contextName = config.CurrentContext
	}
	base := filepath.Dir(path)
	clusterName, userName := "", ""
	found := false
	for _, c := range config.Contexts {
		if c.Name == contextName {
			clusterName, userName, found = c.Context.Cluster, c.Context.User, true
		}
	}
	if !found {
		return nil, fmt.Errorf("the kubeconfig has no context %q", contextName)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	client := &Client{Name: contextName}
	for _, c := range config.Clusters {
		if c.Name != clusterName {
			continue
		}
		client.Server = strings.TrimSuffix(c.Cluster.Server, "/")
		tlsConfig.ServerName = c.Cluster.TLSServerName
		tlsConfig.InsecureSkipVerify = c.Cluster.InsecureSkipTLSVerify
		ca, err := fileOrData(c.Cluster.CertificateAuthorityData, c.Cluster.CertificateAuthority, base)
		if err != nil {
			return nil, fmt.Errorf("read the cluster's CA: %w", err)
		}
		if len(ca) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, errors.New("the cluster's CA is not a PEM certificate")
			}
			tlsConfig.RootCAs = pool
		}
	}
	if client.Server == "" {
		return nil, fmt.Errorf("the kubeconfig has no cluster %q", clusterName)
	}
	for _, u := range config.Users {
		if u.Name != userName {
			continue
		}
		user := u.User
		switch {
		case user.AuthProvider != nil:
			return nil, errors.New("the kubeconfig uses an auth-provider, which kubectl removed; use an exec plugin such as gke-gcloud-auth-plugin or kubelogin")
		case user.Exec != nil:
			exec := user.Exec
			env := os.Environ()
			for _, e := range exec.Env {
				env = append(env, e.Name+"="+e.Value)
			}
			client.token = execToken(exec.Command, exec.Args, env, exec.APIVersion, base)
		case user.Token != "":
			token := user.Token
			client.token = func(context.Context) (string, error) { return token, nil }
		case user.TokenFile != "":
			file := user.TokenFile
			client.token = func(context.Context) (string, error) {
				data, err := os.ReadFile(file)
				return strings.TrimSpace(string(data)), err
			}
		case user.Username != "":
			basic := base64.StdEncoding.EncodeToString([]byte(user.Username + ":" + user.Password))
			client.token = func(context.Context) (string, error) { return "Basic " + basic, nil }
		}
		certificate, err := fileOrData(user.ClientCertificateData, user.ClientCertificate, base)
		if err != nil {
			return nil, fmt.Errorf("read the client certificate: %w", err)
		}
		key, err := fileOrData(user.ClientKeyData, user.ClientKey, base)
		if err != nil {
			return nil, fmt.Errorf("read the client key: %w", err)
		}
		if len(certificate) > 0 {
			pair, err := tls.X509KeyPair(certificate, key)
			if err != nil {
				return nil, fmt.Errorf("the client certificate and key: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		}
	}
	client.http = &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}}
	return client, nil
}

// execToken runs a kubeconfig exec plugin, as kubectl does, and keeps its
// token until it expires.
func execToken(command string, args, env []string, apiVersion, base string) func(context.Context) (string, error) {
	var mu sync.Mutex
	var token string
	var expires time.Time
	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if token != "" && (expires.IsZero() || time.Now().Add(time.Minute).Before(expires)) {
			return token, nil
		}
		if apiVersion == "" {
			apiVersion = "client.authentication.k8s.io/v1"
		}
		if strings.Contains(command, "/") && !filepath.IsAbs(command) {
			command = filepath.Join(base, command)
		}
		run := exec.CommandContext(ctx, command, args...)
		info, _ := json.Marshal(map[string]any{"apiVersion": apiVersion, "kind": "ExecCredential", "spec": map[string]any{"interactive": false}})
		run.Env = append(env, "KUBERNETES_EXEC_INFO="+string(info))
		var stderr bytes.Buffer
		run.Stderr = &stderr
		output, err := run.Output()
		if err != nil {
			return "", fmt.Errorf("the kubeconfig's exec plugin %s failed: %v %s", command, err, strings.TrimSpace(stderr.String()))
		}
		var credential struct {
			Status struct {
				Token               string `json:"token"`
				ExpirationTimestamp string `json:"expirationTimestamp"`
			} `json:"status"`
		}
		if err := json.Unmarshal(output, &credential); err != nil || credential.Status.Token == "" {
			return "", fmt.Errorf("the kubeconfig's exec plugin %s gave no token (client certificates from plugins aren't supported)", command)
		}
		token = credential.Status.Token
		expires, _ = time.Parse(time.RFC3339, credential.Status.ExpirationTimestamp)
		return token, nil
	}
}

// ErrForbidden means the account may not list a kind of object.
var ErrForbidden = errors.New("forbidden")

// Get reads one API path into value.
func (c *Client) Get(ctx context.Context, path string, value any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Server+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	if c.token != nil {
		token, err := c.token(ctx)
		if err != nil {
			return err
		}
		if strings.HasPrefix(token, "Basic ") {
			request.Header.Set("Authorization", token)
		} else if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("reach the Kubernetes API at %s: %w", c.Server, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256<<20))
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusOK:
		return json.Unmarshal(body, value)
	case http.StatusUnauthorized:
		return fmt.Errorf("the Kubernetes API refused the login (401): check the kubeconfig's user")
	case http.StatusForbidden:
		return fmt.Errorf("%s: %w", path, ErrForbidden)
	case http.StatusNotFound:
		return fmt.Errorf("%s: %w", path, os.ErrNotExist)
	}
	return fmt.Errorf("the Kubernetes API answered %s for %s", response.Status, path)
}

// List reads every object at a list path, page by page, as raw JSON.
func (c *Client) List(ctx context.Context, path string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	next := ""
	for {
		query := url.Values{"limit": {"500"}}
		if next != "" {
			query.Set("continue", next)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []json.RawMessage `json:"items"`
		}
		if err := c.Get(ctx, path+"?"+query.Encode(), &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.Metadata.Continue == "" {
			return all, nil
		}
		next = page.Metadata.Continue
	}
}

// Version is the API server's version.
type Version struct {
	GitVersion string `json:"gitVersion"`
	Platform   string `json:"platform"`
}

// ServerVersion reads /version.
func (c *Client) ServerVersion(ctx context.Context) (Version, error) {
	var version Version
	err := c.Get(ctx, "/version", &version)
	return version, err
}
