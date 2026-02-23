// Package tced provides an interface to Tencent Cloud Enterprise Drive.
package tced

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Young-Lord/rclone-tced-oot/backend/tced/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

const (
	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2

	defaultURL       = "https://pan.sjtu.edu.cn"
	defaultListChunk = 200

	providerOther = "other"
	providerSJTU  = "sjtu"

	authTypeUserToken    = "USER_TOKEN"
	authTypeJAAuthCookie = "JAAuthCookie"

	defaultSJTUSSOClientID    = "xpw8ou8y"
	defaultSJTUSSOCustomState = "4ycSqbzfqM9mPuzOKmvTUQ%25253D%25253D"
	defaultSJTUDeviceID       = "Chrome 116.0.0.0"

	defaultEncoding = encoder.Display |
		encoder.EncodeCtl |
		encoder.EncodeBackSlash |
		encoder.EncodeDoubleQuote |
		encoder.EncodeAsterisk |
		encoder.EncodeColon |
		encoder.EncodeLtGt |
		encoder.EncodeQuestion |
		encoder.EncodePipe |
		encoder.EncodeDel |
		encoder.EncodeInvalidUtf8
)

// retryErrorCodes is a slice of status codes that should be retried.
var retryErrorCodes = []int{
	429,
	500,
	502,
	503,
	504,
	509,
}

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "tced",
		Description: "Tencent Cloud Enterprise Drive",
		NewFs:       NewFs,
		Config:      configAuth,
		Options: []fs.Option{{
			Name: "url",
			Help: `API endpoint base URL.

For SJTU provider the default is https://pan.sjtu.edu.cn.
For other providers set this to your TCED deployment URL.`,
			Default: defaultURL,
		}, {
			Name: "provider",
			Help: "TCED provider profile.",
			Examples: []fs.OptionExample{{
				Value: providerOther,
				Help:  "Other provider",
			}, {
				Value: providerSJTU,
				Help:  "SJTU Netdisk",
			}},
			Default: providerOther,
		}, {
			Name:     "auth_type",
			Help:     "Authentication type.",
			Provider: providerSJTU,
			Examples: []fs.OptionExample{{
				Value: authTypeUserToken,
				Help:  "Authenticate with user_token",
			}, {
				Value: authTypeJAAuthCookie,
				Help:  "Authenticate with JAAuthCookie (SJTU provider only)",
			}},
			Default: authTypeUserToken,
		}, {
			Name:      "user_token",
			Help:      "TCED user token used by USER_TOKEN auth.",
			Hide:      fs.OptionHideConfigurator,
			Sensitive: true,
		}, {
			Name:      "ja_auth_cookie",
			Help:      "SJTU JAAuthCookie used by JAAuthCookie auth.",
			Provider:  providerSJTU,
			Hide:      fs.OptionHideConfigurator,
			Sensitive: true,
		}, {
			Name:     "list_chunk",
			Help:     "Number of entries fetched per list request.",
			Default:  defaultListChunk,
			Advanced: true,
		}, {
			Name:     "pacer_min_sleep",
			Help:     "Minimum time to sleep between API calls.",
			Default:  fs.Duration(minSleep),
			Advanced: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Default:  defaultEncoding,
			Advanced: true,
		}},
	})
}

// Options defines the configuration for this backend.
type Options struct {
	URL           string               `config:"url"`
	Provider      string               `config:"provider"`
	AuthType      string               `config:"auth_type"`
	UserToken     string               `config:"user_token"`
	JAAuthCookie  string               `config:"ja_auth_cookie"`
	ListChunk     int                  `config:"list_chunk"`
	PacerMinSleep fs.Duration          `config:"pacer_min_sleep"`
	Enc           encoder.MultiEncoder `config:"encoding"`
}

// Fs represents a TCED remote.
type Fs struct {
	name     string
	root     string
	opt      Options
	features *fs.Features

	srv   *rest.Client
	pacer *fs.Pacer

	authMu sync.Mutex

	userToken       string
	userTokenExpiry time.Time

	accessToken       string
	accessTokenExpiry time.Time
	libraryID         string
	spaceID           string
}

// Object describes a TCED object.
type Object struct {
	fs          *Fs
	remote      string
	hasMetaData bool

	size     int64
	modTime  time.Time
	mimeType string
}

// Name of the remote (as passed into NewFs).
func (f *Fs) Name() string { return f.name }

// Root of the remote (as passed into NewFs).
func (f *Fs) Root() string { return f.root }

// String converts this Fs to a string.
func (f *Fs) String() string {
	return fmt.Sprintf("tced root %q", f.root)
}

// Features returns optional features of this Fs.
func (f *Fs) Features() *fs.Features { return f.features }

// Precision returns modtime precision.
func (f *Fs) Precision() time.Duration { return fs.ModTimeNotSupported }

// Hashes returns supported hashes.
func (f *Fs) Hashes() hash.Set { return hash.Set(hash.None) }

func parsePath(in string) string {
	return strings.Trim(in, "/")
}

func normalizeProvider(in string) string {
	provider := strings.ToLower(strings.TrimSpace(in))
	if provider == "" {
		return providerOther
	}
	return provider
}

func normalizeAuthType(in string) (string, error) {
	compact := strings.ToLower(strings.TrimSpace(in))
	compact = strings.ReplaceAll(compact, "_", "")
	compact = strings.ReplaceAll(compact, "-", "")
	switch compact {
	case "", "usertoken":
		return authTypeUserToken, nil
	case "jaauthcookie", "jacookie":
		return authTypeJAAuthCookie, nil
	default:
		return "", fmt.Errorf("unsupported auth_type %q", in)
	}
}

func validateOptions(opt *Options) error {
	opt.Provider = normalizeProvider(opt.Provider)
	switch opt.Provider {
	case providerOther, providerSJTU:
	default:
		return fmt.Errorf("unsupported provider %q", opt.Provider)
	}

	authType, err := normalizeAuthType(opt.AuthType)
	if err != nil {
		return err
	}
	opt.AuthType = authType

	if opt.Provider == providerOther && opt.AuthType != authTypeUserToken {
		return errors.New("provider=other only supports auth_type=USER_TOKEN")
	}
	if opt.AuthType == authTypeJAAuthCookie && opt.Provider != providerSJTU {
		return errors.New("auth_type=JAAuthCookie is only available for provider=sjtu")
	}

	if opt.AuthType == authTypeUserToken && strings.TrimSpace(opt.UserToken) == "" {
		return errors.New("user_token is required when auth_type=USER_TOKEN")
	}
	if opt.AuthType == authTypeJAAuthCookie && strings.TrimSpace(opt.JAAuthCookie) == "" {
		return errors.New("ja_auth_cookie is required when auth_type=JAAuthCookie")
	}

	if strings.TrimSpace(opt.URL) == "" {
		opt.URL = defaultURL
	}
	if opt.ListChunk <= 0 {
		opt.ListChunk = defaultListChunk
	}
	return nil
}

func authCredentialPrompt(m configmap.Mapper) (configKey, help string) {
	provider, _ := m.Get("provider")
	provider = normalizeProvider(provider)

	authType := authTypeUserToken
	if provider == providerSJTU {
		authTypeValue, _ := m.Get("auth_type")
		if normalized, err := normalizeAuthType(authTypeValue); err == nil {
			authType = normalized
		}
	} else {
		m.Set("auth_type", authTypeUserToken)
	}

	if authType == authTypeJAAuthCookie {
		return "ja_auth_cookie", "SJTU JAAuthCookie used by JAAuthCookie auth."
	}
	return "user_token", "TCED user token used by USER_TOKEN auth."
}

func configAuth(_ context.Context, _ string, m configmap.Mapper, configIn fs.ConfigIn) (*fs.ConfigOut, error) {
	switch configIn.State {
	case "":
		configKey, help := authCredentialPrompt(m)
		if value, ok := m.Get(configKey); ok && strings.TrimSpace(value) != "" {
			return nil, nil
		}
		return &fs.ConfigOut{
			State: "set_auth_credential",
			Option: &fs.Option{
				Name:      configKey,
				Help:      help,
				Required:  true,
				Sensitive: true,
			},
		}, nil
	case "set_auth_credential":
		credential := strings.TrimSpace(configIn.Result)
		if credential == "" {
			return fs.ConfigError("set_auth_credential", "Value must not be empty")
		}
		configKey, _ := authCredentialPrompt(m)
		m.Set(configKey, credential)
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown state %q", configIn.State)
	}
}

// NewFs constructs an Fs from the path.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return nil, err
	}
	if err := validateOptions(opt); err != nil {
		return nil, err
	}

	rootIsDir := strings.HasSuffix(root, "/")
	root = parsePath(root)

	client := fshttp.NewClient(ctx)
	f := &Fs{
		name:  name,
		root:  root,
		opt:   *opt,
		srv:   rest.NewClient(client).SetRoot(strings.TrimRight(opt.URL, "/")),
		pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(time.Duration(opt.PacerMinSleep)), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
		ReadMimeType:            true,
	}).Fill(ctx, f)
	f.srv.SetErrorHandler(errorHandler)

	if err := f.refreshSession(ctx, false); err != nil {
		return nil, err
	}

	if root != "" && !rootIsDir {
		info, err := f.getItemInfo(ctx, f.remoteToAbsolute(""))
		if err != nil {
			if errors.Is(err, fs.ErrorObjectNotFound) {
				return f, nil
			}
			return nil, err
		}
		if info.Type == api.ItemTypeFile {
			f.root = path.Dir(root)
			if f.root == "." {
				f.root = ""
			}
			return f, fs.ErrorIsFile
		}
	}

	return f, nil
}

func expiryFromSeconds(seconds int64) time.Time {
	if seconds <= 0 {
		return time.Now()
	}
	d := time.Duration(seconds) * time.Second
	if d > 30*time.Second {
		d -= 30 * time.Second
	}
	return time.Now().Add(d)
}

func (f *Fs) ensureSession(ctx context.Context) error {
	if f.accessToken != "" && f.libraryID != "" && f.spaceID != "" && time.Now().Before(f.accessTokenExpiry) {
		return nil
	}
	return f.refreshSession(ctx, false)
}

func (f *Fs) refreshSession(ctx context.Context, forceUserToken bool) error {
	f.authMu.Lock()
	defer f.authMu.Unlock()

	if !forceUserToken && f.accessToken != "" && f.libraryID != "" && f.spaceID != "" && time.Now().Before(f.accessTokenExpiry) {
		return nil
	}

	if forceUserToken {
		f.userToken = ""
		f.userTokenExpiry = time.Time{}
	}

	switch f.opt.AuthType {
	case authTypeUserToken:
		f.userToken = f.opt.UserToken
		f.userTokenExpiry = time.Time{}
	case authTypeJAAuthCookie:
		if f.userToken == "" || time.Now().After(f.userTokenExpiry) {
			token, expiresIn, err := f.fetchSJTUUserToken(ctx)
			if err != nil {
				return err
			}
			f.userToken = token
			f.userTokenExpiry = expiryFromSeconds(expiresIn)
		}
	default:
		return fmt.Errorf("unsupported auth_type %q", f.opt.AuthType)
	}

	cred, err := f.fetchSpaceCredential(ctx, f.userToken)
	if err != nil {
		if f.opt.AuthType == authTypeJAAuthCookie && isInvalidUserToken(err) {
			token, expiresIn, tokenErr := f.fetchSJTUUserToken(ctx)
			if tokenErr != nil {
				return tokenErr
			}
			f.userToken = token
			f.userTokenExpiry = expiryFromSeconds(expiresIn)
			cred, err = f.fetchSpaceCredential(ctx, f.userToken)
		}
		if err != nil {
			return err
		}
	}

	f.accessToken = cred.AccessToken
	f.accessTokenExpiry = expiryFromSeconds(cred.ExpiresIn)
	f.libraryID = cred.LibraryID
	f.spaceID = cred.SpaceID
	return nil
}

func (f *Fs) fetchSJTUUserToken(ctx context.Context) (token string, expiresIn int64, err error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", 0, err
	}
	jaCookieURL := &url.URL{Scheme: "https", Host: "jaccount.sjtu.edu.cn", Path: "/"}
	jar.SetCookies(jaCookieURL, []*http.Cookie{{
		Name:     "JAAuthCookie",
		Value:    f.opt.JAAuthCookie,
		Path:     "/",
		Domain:   "jaccount.sjtu.edu.cn",
		Secure:   true,
		HttpOnly: true,
	}})

	client := &http.Client{
		Transport: fshttp.NewTransport(ctx),
		Jar:       jar,
		Timeout:   30 * time.Second,
	}

	base := strings.TrimRight(f.opt.URL, "/")
	redirectURL := fmt.Sprintf("%s/user/v1/sign-in/sso-login-redirect/%s?auto_redirect=true&from=web&custom_state=%s", base, url.PathEscape(defaultSJTUSSOClientID), defaultSJTUSSOCustomState)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirectURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	_ = resp.Body.Close()

	finalURL := resp.Request.URL
	if strings.Contains(strings.ToLower(finalURL.Host), "jaccount") {
		return "", 0, errors.New("JAAuthCookie authentication failed: redirected back to jAccount")
	}

	code := finalURL.Query().Get("code")
	if code == "" {
		return "", 0, errors.New("JAAuthCookie authentication failed: callback code not found")
	}

	verifyURL := fmt.Sprintf("%s/user/v1/sign-in/verify-account-login/%s?device_id=%s&type=sso&credential=%s",
		base,
		url.PathEscape(defaultSJTUSSOClientID),
		url.QueryEscape(defaultSJTUDeviceID),
		url.QueryEscape(code),
	)
	verifyReq, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, nil)
	if err != nil {
		return "", 0, err
	}
	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		return "", 0, err
	}
	defer fs.CheckClose(verifyResp.Body, &err)

	if verifyResp.StatusCode < 200 || verifyResp.StatusCode >= 300 {
		return "", 0, parseHTTPAPIError(verifyResp)
	}

	var out api.UserTokenResponse
	if decodeErr := json.NewDecoder(verifyResp.Body).Decode(&out); decodeErr != nil {
		return "", 0, decodeErr
	}
	if out.UserToken == "" {
		return "", 0, errors.New("JAAuthCookie authentication failed: empty user token")
	}
	return out.UserToken, out.ExpiresIn, nil
}

func (f *Fs) fetchSpaceCredential(ctx context.Context, userToken string) (*api.SpaceCredential, error) {
	if userToken == "" {
		return nil, errors.New("empty user token")
	}
	opts := rest.Opts{
		Method: "POST",
		Path:   "/user/v1/space/1/personal",
		Parameters: url.Values{
			"user_token": {userToken},
		},
	}
	var out api.SpaceCredential
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &out)
		return shouldRetryNoReauth(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}
	if out.AccessToken == "" || out.LibraryID == "" || out.SpaceID == "" {
		return nil, errors.New("invalid response from space credential API")
	}
	return &out, nil
}

func (f *Fs) getSpaceInfo(ctx context.Context) (*api.SpaceInfo, error) {
	if err := f.ensureSession(ctx); err != nil {
		return nil, err
	}
	opts := rest.Opts{
		Method: "GET",
		Path:   "/user/v1/space/1",
		Parameters: url.Values{
			"user_token": {f.userToken},
		},
	}
	var out api.SpaceInfo
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &out)
		if isInvalidUserToken(err) && f.opt.AuthType == authTypeJAAuthCookie {
			refreshErr := f.refreshSession(ctx, true)
			if refreshErr != nil {
				return false, refreshErr
			}
			opts.Parameters.Set("user_token", f.userToken)
			return true, err
		}
		return shouldRetryNoReauth(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func shouldRetryNoReauth(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

func (f *Fs) shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	if isInvalidAccessToken(err) {
		refreshErr := f.refreshSession(ctx, false)
		if refreshErr != nil {
			return false, refreshErr
		}
		return true, err
	}
	if isInvalidUserToken(err) && f.opt.AuthType == authTypeJAAuthCookie {
		refreshErr := f.refreshSession(ctx, true)
		if refreshErr != nil {
			return false, refreshErr
		}
		return true, err
	}
	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

func errorHandler(resp *http.Response) error {
	body, err := rest.ReadBody(resp)
	if err != nil {
		return err
	}
	errResponse := new(api.Error)
	if len(body) > 0 {
		if decodeErr := json.Unmarshal(body, errResponse); decodeErr != nil {
			errResponse.Message = strings.TrimSpace(string(body))
		}
	}
	if errResponse.Status == 0 {
		errResponse.Status = resp.StatusCode
	}
	if errResponse.Message == "" {
		errResponse.Message = resp.Status
	}
	return errResponse
}

func parseHTTPAPIError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	apiErr := new(api.Error)
	if len(body) > 0 {
		if decodeErr := json.Unmarshal(body, apiErr); decodeErr != nil {
			apiErr.Message = strings.TrimSpace(string(body))
		}
	}
	if apiErr.Status == 0 {
		apiErr.Status = resp.StatusCode
	}
	if apiErr.Message == "" {
		apiErr.Message = resp.Status
	}
	return apiErr
}

func asAPIError(err error) *api.Error {
	if err == nil {
		return nil
	}
	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return nil
}

func isInvalidAccessToken(err error) bool {
	apiErr := asAPIError(err)
	return apiErr != nil && apiErr.Code == "InvalidAccessToken"
}

func isInvalidUserToken(err error) bool {
	apiErr := asAPIError(err)
	return apiErr != nil && apiErr.Code == "InvalidUserToken"
}

func isNotFound(err error) bool {
	apiErr := asAPIError(err)
	if apiErr == nil {
		return false
	}
	if apiErr.Status == http.StatusNotFound {
		return true
	}
	return strings.Contains(strings.ToLower(apiErr.Code), "notfound")
}

func (f *Fs) remoteToAbsolute(remote string) string {
	p := path.Join("/", f.root, remote)
	if p == "." {
		return "/"
	}
	return p
}

func (f *Fs) standardToProviderPath(absPath string) string {
	clean := path.Clean("/" + strings.TrimPrefix(absPath, "/"))
	if clean == "/" {
		return "/"
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for i, part := range parts {
		parts[i] = f.opt.Enc.FromStandardName(part)
	}
	return "/" + strings.Join(parts, "/")
}

func (f *Fs) encodeProviderPath(providerPath string) string {
	clean := path.Clean("/" + strings.TrimPrefix(providerPath, "/"))
	if clean == "/" {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func (f *Fs) encodedPath(absPath string) string {
	providerPath := f.standardToProviderPath(absPath)
	return f.encodeProviderPath(providerPath)
}

func (f *Fs) directoryPath(absPath string) string {
	return fmt.Sprintf("/api/v1/directory/%s/%s/%s", url.PathEscape(f.libraryID), url.PathEscape(f.spaceID), f.encodedPath(absPath))
}

func (f *Fs) filePath(absPath string) string {
	return fmt.Sprintf("/api/v1/file/%s/%s/%s", url.PathEscape(f.libraryID), url.PathEscape(f.spaceID), f.encodedPath(absPath))
}

func (f *Fs) getItemInfo(ctx context.Context, absPath string) (*api.Item, error) {
	opts := rest.Opts{
		Method: "GET",
		Path:   f.directoryPath(absPath),
		Parameters: url.Values{
			"info": {""},
		},
	}
	var out api.Item
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &out)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		if isNotFound(err) {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, fmt.Errorf("get item info failed: %w", err)
	}
	if out.Type == "" {
		return nil, fs.ErrorObjectNotFound
	}
	return &out, nil
}

func (f *Fs) listDirectoryPage(ctx context.Context, absDir string, page int) (*api.ListResult, error) {
	opts := rest.Opts{
		Method: "GET",
		Path:   f.directoryPath(absDir),
		Parameters: url.Values{
			"page":          {strconv.Itoa(page)},
			"page_size":     {strconv.Itoa(f.opt.ListChunk)},
			"order_by":      {"name"},
			"order_by_type": {"asc"},
		},
	}
	var out api.ListResult
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &out)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		if isNotFound(err) {
			return nil, fs.ErrorDirNotFound
		}
		return nil, fmt.Errorf("list directory failed: %w", err)
	}
	return &out, nil
}

func (f *Fs) createDirectory(ctx context.Context, absDir string) error {
	opts := rest.Opts{
		Method: "PUT",
		Path:   f.directoryPath(absDir),
		Parameters: url.Values{
			"conflict_resolution_strategy": {"ask"},
		},
		NoResponse: true,
	}
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		resp, err = f.srv.Call(ctx, &opts)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return fmt.Errorf("create directory failed: %w", err)
	}
	return nil
}

func (f *Fs) mkdir(ctx context.Context, absDir string) error {
	clean := path.Clean("/" + strings.TrimPrefix(absDir, "/"))
	if clean == "/" {
		return nil
	}

	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	current := ""
	for _, part := range parts {
		current = path.Join(current, part)
		currentAbs := "/" + current
		err := f.createDirectory(ctx, currentAbs)
		if err == nil {
			continue
		}
		apiErr := asAPIError(err)
		if apiErr != nil && apiErr.Code == "SameNameDirectoryOrFileExists" {
			item, infoErr := f.getItemInfo(ctx, currentAbs)
			if infoErr != nil {
				return infoErr
			}
			if item.Type != api.ItemTypeDir {
				return fs.ErrorIsFile
			}
			continue
		}
		return err
	}
	return nil
}

func (f *Fs) dirNotEmpty(ctx context.Context, absDir string) (bool, error) {
	result, err := f.listDirectoryPage(ctx, absDir, 1)
	if err != nil {
		return false, err
	}
	return result.TotalNum > 0 || len(result.Contents) > 0, nil
}

func (f *Fs) deletePath(ctx context.Context, absPath string) error {
	opts := rest.Opts{
		Method: "DELETE",
		Path:   f.filePath(absPath),
		Parameters: url.Values{
			"permanent": {"0"},
		},
		NoResponse: true,
	}
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		resp, err = f.srv.Call(ctx, &opts)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		if isNotFound(err) {
			return fs.ErrorObjectNotFound
		}
		return fmt.Errorf("delete failed: %w", err)
	}
	return nil
}

func (f *Fs) startSimpleUpload(ctx context.Context, absPath string) (*api.StartSimpleUploadResult, error) {
	opts := rest.Opts{
		Method: "PUT",
		Path:   f.filePath(absPath),
		Parameters: url.Values{
			"conflict_resolution_strategy": {"overwrite"},
		},
		Body: bytes.NewBufferString("{}"),
	}
	var out api.StartSimpleUploadResult
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		opts.ContentType = "application/json"
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &out)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, fmt.Errorf("start upload failed: %w", err)
	}
	if out.ConfirmKey == "" || out.Domain == "" || out.Path == "" {
		return nil, errors.New("start upload failed: incomplete response")
	}
	return &out, nil
}

func (f *Fs) uploadToSignedURL(ctx context.Context, signed *api.StartSimpleUploadResult, in io.Reader, size int64, contentType string, options ...fs.OpenOption) error {
	extraHeaders := map[string]string{}
	for k, v := range signed.Headers {
		extraHeaders[k] = v
	}
	if _, found := extraHeaders["content-type"]; !found {
		if _, found := extraHeaders["Content-Type"]; !found && contentType != "" {
			extraHeaders["Content-Type"] = contentType
		}
	}

	uploadURL := "https://" + signed.Domain + signed.Path
	opts := rest.Opts{
		Method:       "PUT",
		RootURL:      uploadURL,
		Body:         in,
		NoResponse:   true,
		ExtraHeaders: extraHeaders,
		Options:      options,
	}
	if size >= 0 {
		opts.ContentLength = &size
	}

	return f.pacer.CallNoRetry(func() (bool, error) {
		_, err := f.srv.Call(ctx, &opts)
		return false, err
	})
}

func (f *Fs) confirmUpload(ctx context.Context, confirmKey string) (*api.Item, error) {
	confirmPath := fmt.Sprintf("/api/v1/file/%s/%s/%s", url.PathEscape(f.libraryID), url.PathEscape(f.spaceID), url.PathEscape(confirmKey))
	opts := rest.Opts{
		Method: "POST",
		Path:   confirmPath,
		Parameters: url.Values{
			"confirm":                      {""},
			"conflict_resolution_strategy": {"overwrite"},
		},
	}
	var out api.Item
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &out)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, fmt.Errorf("confirm upload failed: %w", err)
	}
	return &out, nil
}

func (f *Fs) copyOrMovePath(ctx context.Context, srcProviderPath, dstAbsPath string, move bool) error {
	request := api.CopyMoveRequest{}
	if move {
		request.From = srcProviderPath
	} else {
		request.CopyFrom = srcProviderPath
	}

	opts := rest.Opts{
		Method: "PUT",
		Path:   f.filePath(dstAbsPath),
		Parameters: url.Values{
			"conflict_resolution_strategy": {"overwrite"},
		},
	}
	var out map[string]any
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		resp, err = f.srv.CallJSON(ctx, &opts, &request, &out)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		if isNotFound(err) {
			return fs.ErrorObjectNotFound
		}
		return fmt.Errorf("copy/move failed: %w", err)
	}
	return nil
}

func (f *Fs) moveDirPath(ctx context.Context, srcProviderPath, dstAbsPath string) error {
	request := api.CopyMoveRequest{
		From: srcProviderPath,
	}
	opts := rest.Opts{
		Method: "PUT",
		Path:   f.directoryPath(dstAbsPath),
		Parameters: url.Values{
			"conflict_resolution_strategy": {"ask"},
		},
		NoResponse: true,
	}
	var resp *http.Response
	var err error
	err = f.pacer.Call(func() (bool, error) {
		if err := f.ensureSession(ctx); err != nil {
			return false, err
		}
		opts.Parameters.Set("access_token", f.accessToken)
		resp, err = f.srv.CallJSON(ctx, &opts, &request, nil)
		return f.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		if isNotFound(err) {
			return fs.ErrorObjectNotFound
		}
		return fmt.Errorf("directory move failed: %w", err)
	}
	return nil
}

func (f *Fs) itemToDirEntry(ctx context.Context, dir string, item *api.Item) (fs.DirEntry, error) {
	name := f.opt.Enc.ToStandardName(item.Name)
	remote := path.Join(dir, name)
	switch item.Type {
	case api.ItemTypeDir:
		return fs.NewDir(remote, item.ModificationTime.Value()), nil
	case api.ItemTypeFile:
		o := &Object{fs: f, remote: remote}
		if err := o.setMetaData(item); err != nil {
			return nil, err
		}
		return o, nil
	default:
		return nil, nil
	}
}

// NewObject finds the Object at remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	o := &Object{fs: f, remote: remote}
	if err := o.readMetaData(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

// List the objects and directories in dir into entries.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	absDir := f.remoteToAbsolute(dir)
	page := 1
	for {
		result, err := f.listDirectoryPage(ctx, absDir, page)
		if err != nil {
			return nil, err
		}
		for i := range result.Contents {
			entry, err := f.itemToDirEntry(ctx, dir, &result.Contents[i])
			if err != nil {
				return nil, err
			}
			if entry != nil {
				entries = append(entries, entry)
			}
		}
		if len(result.Contents) == 0 || int64(page*f.opt.ListChunk) >= result.TotalNum {
			break
		}
		page++
	}
	return entries, nil
}

// Put uploads an object.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	existing, err := f.NewObject(ctx, src.Remote())
	switch err {
	case nil:
		return existing, existing.Update(ctx, in, src, options...)
	case fs.ErrorObjectNotFound:
		o := &Object{fs: f, remote: src.Remote()}
		return o, o.Update(ctx, in, src, options...)
	default:
		return nil, err
	}
}

// PutStream uploads an object of unknown size.
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.Put(ctx, in, src, options...)
}

// Mkdir creates a directory if it doesn't exist.
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return f.mkdir(ctx, f.remoteToAbsolute(dir))
}

// Rmdir deletes a directory if empty.
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	absDir := f.remoteToAbsolute(dir)
	if absDir == "/" {
		return errors.New("can't rmdir root directory")
	}
	info, err := f.getItemInfo(ctx, absDir)
	if err != nil {
		if errors.Is(err, fs.ErrorObjectNotFound) {
			return fs.ErrorDirNotFound
		}
		return err
	}
	if info.Type != api.ItemTypeDir {
		return fs.ErrorIsFile
	}
	notEmpty, err := f.dirNotEmpty(ctx, absDir)
	if err != nil {
		if errors.Is(err, fs.ErrorDirNotFound) {
			return fs.ErrorDirNotFound
		}
		return err
	}
	if notEmpty {
		return fs.ErrorDirectoryNotEmpty
	}
	err = f.deletePath(ctx, absDir)
	if errors.Is(err, fs.ErrorObjectNotFound) {
		return fs.ErrorDirNotFound
	}
	return err
}

// purgeCheck removes dir and optionally checks emptiness.
func (f *Fs) purgeCheck(ctx context.Context, dir string, check bool) error {
	absDir := f.remoteToAbsolute(dir)
	if absDir == "/" {
		return errors.New("can't purge root directory")
	}
	info, err := f.getItemInfo(ctx, absDir)
	if err != nil {
		if errors.Is(err, fs.ErrorObjectNotFound) {
			return fs.ErrorDirNotFound
		}
		return err
	}
	if info.Type != api.ItemTypeDir {
		return fs.ErrorIsFile
	}
	if check {
		notEmpty, err := f.dirNotEmpty(ctx, absDir)
		if err != nil {
			if errors.Is(err, fs.ErrorDirNotFound) {
				return fs.ErrorDirNotFound
			}
			return err
		}
		if notEmpty {
			return fs.ErrorDirectoryNotEmpty
		}
	}
	err = f.deletePath(ctx, absDir)
	if errors.Is(err, fs.ErrorObjectNotFound) {
		return fs.ErrorDirNotFound
	}
	return err
}

// Purge deletes all files in dir.
func (f *Fs) Purge(ctx context.Context, dir string) error {
	return f.purgeCheck(ctx, dir, false)
}

// About gets quota information.
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	spaceInfo, err := f.getSpaceInfo(ctx)
	if err != nil {
		return nil, err
	}
	used := spaceInfo.Size.Value()
	total := spaceInfo.Capacity.Value()
	usage := &fs.Usage{
		Used: fs.NewUsageValue(used),
	}
	if total > 0 {
		usage.Total = fs.NewUsageValue(total)
		usage.Free = fs.NewUsageValue(total - used)
	}
	return usage, nil
}

// Copy src to this remote using server-side copy.
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantCopy
	}
	if srcObj.fs.libraryID != f.libraryID || srcObj.fs.spaceID != f.spaceID {
		return nil, fs.ErrorCantCopy
	}
	srcAbs := srcObj.fs.remoteToAbsolute(srcObj.remote)
	srcProviderPath := srcObj.fs.standardToProviderPath(srcAbs)
	dstAbs := f.remoteToAbsolute(remote)
	if srcAbs == dstAbs && srcObj.fs.root == f.root {
		return nil, errors.New("can't copy to the same path")
	}
	if err := f.mkdir(ctx, path.Dir(dstAbs)); err != nil {
		return nil, err
	}
	if err := f.copyOrMovePath(ctx, srcProviderPath, dstAbs, false); err != nil {
		return nil, err
	}
	return f.NewObject(ctx, remote)
}

// Move src to this remote using server-side move.
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantMove
	}
	if srcObj.fs.libraryID != f.libraryID || srcObj.fs.spaceID != f.spaceID {
		return nil, fs.ErrorCantMove
	}
	srcAbs := srcObj.fs.remoteToAbsolute(srcObj.remote)
	srcProviderPath := srcObj.fs.standardToProviderPath(srcAbs)
	dstAbs := f.remoteToAbsolute(remote)
	if srcAbs == dstAbs && srcObj.fs.root == f.root {
		return nil, errors.New("can't move to the same path")
	}
	if err := f.mkdir(ctx, path.Dir(dstAbs)); err != nil {
		return nil, err
	}
	if err := f.copyOrMovePath(ctx, srcProviderPath, dstAbs, true); err != nil {
		return nil, err
	}
	return f.NewObject(ctx, remote)
}

// DirMove moves srcRemote directory from src to this remote at dstRemote.
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	srcFs, ok := src.(*Fs)
	if !ok {
		return fs.ErrorCantDirMove
	}
	if srcFs.libraryID != f.libraryID || srcFs.spaceID != f.spaceID {
		return fs.ErrorCantDirMove
	}
	srcAbs := srcFs.remoteToAbsolute(srcRemote)
	srcProviderPath := srcFs.standardToProviderPath(srcAbs)
	dstAbs := f.remoteToAbsolute(dstRemote)
	if srcAbs == "/" {
		return fs.ErrorCantDirMove
	}
	_, err := f.getItemInfo(ctx, dstAbs)
	if err == nil {
		return fs.ErrorDirExists
	}
	if !errors.Is(err, fs.ErrorObjectNotFound) {
		return err
	}
	if err := f.mkdir(ctx, path.Dir(dstAbs)); err != nil {
		return err
	}
	return f.moveDirPath(ctx, srcProviderPath, dstAbs)
}

// Fs returns the parent Fs.
func (o *Object) Fs() fs.Info { return o.fs }

// String returns string form.
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns remote path.
func (o *Object) Remote() string { return o.remote }

// Hash returns object hash if supported.
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Size returns object size.
func (o *Object) Size() int64 {
	return o.size
}

func (o *Object) setMetaData(info *api.Item) error {
	if info == nil {
		return errors.New("nil metadata")
	}
	if info.Type == api.ItemTypeDir {
		return fs.ErrorIsDir
	}
	if info.Type != api.ItemTypeFile {
		return fmt.Errorf("%q is not a file", o.remote)
	}
	o.hasMetaData = true
	o.size = info.Size.Value()
	o.modTime = info.ModificationTime.Value()
	o.mimeType = info.ContentType
	return nil
}

func (o *Object) readMetaData(ctx context.Context) error {
	if o.hasMetaData {
		return nil
	}
	info, err := o.fs.getItemInfo(ctx, o.fs.remoteToAbsolute(o.remote))
	if err != nil {
		if errors.Is(err, fs.ErrorObjectNotFound) {
			return fs.ErrorObjectNotFound
		}
		return err
	}
	return o.setMetaData(info)
}

// ModTime returns object modification time.
func (o *Object) ModTime(ctx context.Context) time.Time {
	if err := o.readMetaData(ctx); err != nil {
		fs.Infof(o, "Failed to read metadata: %v", err)
		return time.Now()
	}
	return o.modTime
}

// SetModTime sets object modification time.
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable returns whether object is storable.
func (o *Object) Storable() bool { return true }

// MimeType returns the MIME type if known.
func (o *Object) MimeType(ctx context.Context) string {
	if err := o.readMetaData(ctx); err != nil {
		return ""
	}
	return o.mimeType
}

// Open opens object for read.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	if err := o.readMetaData(ctx); err != nil && !errors.Is(err, fs.ErrorObjectNotFound) {
		return nil, err
	}
	fs.FixRangeOption(options, o.size)

	opts := rest.Opts{
		Method:  "GET",
		Path:    o.fs.filePath(o.fs.remoteToAbsolute(o.remote)),
		Options: options,
	}
	var resp *http.Response
	var err error
	err = o.fs.pacer.Call(func() (bool, error) {
		if err := o.fs.ensureSession(ctx); err != nil {
			return false, err
		}
		if opts.Parameters == nil {
			opts.Parameters = url.Values{}
		}
		opts.Parameters.Set("access_token", o.fs.accessToken)
		resp, err = o.fs.srv.Call(ctx, &opts)
		return o.fs.shouldRetry(ctx, resp, err)
	})
	if err != nil {
		if isNotFound(err) {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, err
	}
	return resp.Body, nil
}

// Update updates object content.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	absPath := o.fs.remoteToAbsolute(o.remote)
	if err := o.fs.mkdir(ctx, path.Dir(absPath)); err != nil {
		return err
	}

	start, err := o.fs.startSimpleUpload(ctx, absPath)
	if err != nil {
		return err
	}

	contentType := fs.MimeType(ctx, src)
	if err := o.fs.uploadToSignedURL(ctx, start, in, src.Size(), contentType, options...); err != nil {
		return fmt.Errorf("upload to signed URL failed: %w", err)
	}

	info, err := o.fs.confirmUpload(ctx, start.ConfirmKey)
	if err != nil {
		return err
	}
	if err := o.setMetaData(info); err != nil {
		o.hasMetaData = false
		return o.readMetaData(ctx)
	}
	return nil
}

// Remove removes the object.
func (o *Object) Remove(ctx context.Context) error {
	err := o.fs.deletePath(ctx, o.fs.remoteToAbsolute(o.remote))
	if errors.Is(err, fs.ErrorObjectNotFound) {
		return fs.ErrorObjectNotFound
	}
	return err
}

// Check the interfaces are satisfied.
var (
	_ fs.Fs          = (*Fs)(nil)
	_ fs.Purger      = (*Fs)(nil)
	_ fs.PutStreamer = (*Fs)(nil)
	_ fs.Abouter     = (*Fs)(nil)
	_ fs.Copier      = (*Fs)(nil)
	_ fs.Mover       = (*Fs)(nil)
	_ fs.DirMover    = (*Fs)(nil)
	_ fs.Object      = (*Object)(nil)
	_ fs.MimeTyper   = (*Object)(nil)
)
