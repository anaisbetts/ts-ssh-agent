// Package client talks to a ts-ssh-agent server over the tailnet.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/anaisbetts/ts-ssh-agent/internal/api"
)

const defaultTimeout = 30 * time.Second

type Client struct {
	baseURL string
	http    *http.Client
}

type StatusError struct {
	StatusCode int
	Message    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.StatusCode, e.Message)
}

// New creates a client for the server at baseURL. If httpClient is nil, a
// default client is used, which relies on the host's own tailscaled for
// connectivity to the tailnet.
func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

func (c *Client) WhoAmI(ctx context.Context) (*api.WhoAmIResponse, error) {
	var resp api.WhoAmIResponse
	return &resp, c.do(ctx, http.MethodGet, api.PathWhoAmI, nil, &resp)
}

func (c *Client) ListKeys(ctx context.Context) ([]api.Key, error) {
	var resp api.ListKeysResponse
	return resp.Keys, c.do(ctx, http.MethodGet, api.PathKeys, nil, &resp)
}

func (c *Client) AddKey(ctx context.Context, req *api.AddKeyRequest) (string, error) {
	var resp api.AddKeyResponse
	return resp.Fingerprint, c.do(ctx, http.MethodPost, api.PathKeys, req, &resp)
}

func (c *Client) RemoveKey(ctx context.Context, fingerprint string) (int, error) {
	var resp api.RemoveKeysResponse
	path := api.PathKeys + "?fingerprint=" + url.QueryEscape(fingerprint)
	return resp.Removed, c.do(ctx, http.MethodDelete, path, nil, &resp)
}

func (c *Client) RemoveAllKeys(ctx context.Context) (int, error) {
	var resp api.RemoveKeysResponse
	return resp.Removed, c.do(ctx, http.MethodDelete, api.PathKeys+"?all=true", nil, &resp)
}

func (c *Client) Sign(ctx context.Context, req *api.SignRequest) (*ssh.Signature, error) {
	var resp api.SignResponse
	if err := c.do(ctx, http.MethodPost, api.PathSign, req, &resp); err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: resp.Format, Blob: resp.Blob, Rest: resp.Rest}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e api.ErrorResponse
		if json.NewDecoder(resp.Body).Decode(&e) != nil || e.Error == "" {
			e.Error = resp.Status
		}
		return &StatusError{StatusCode: resp.StatusCode, Message: e.Error}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
