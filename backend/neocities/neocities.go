// Package neocities provides the Neocities rclone backend for managing files
// on Neocities sites.
package neocities

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/backend/neocities/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"
)

// Options represents the authentication configuration used to access a remote
// Neocities site.
type Options struct {
	Username string `config:"username"`
	Password string `config:"password"`
	APIKey   string `config:"api_key"`
}

// Fs represents a connection to a remote Neocities site via the Neocities API.
type Fs struct {
	name     string
	root     string
	options  *Options
	features *fs.Features
	pacer    *fs.Pacer
	client   *http.Client
	auth     string               // HTTP "Authorization" header value.
	host     *url.URL             // URL of the remote host. Eg. "site.neocities.org" or "customdomain.com".
	site     *api.Site            // Remote site info.
	cache    map[string]*api.File // Remote file info cache, map of file path -> file info.
	cachemu  sync.Mutex           // Lock for the file info cache.
}

// Object represents a file in a remote Neocities site.
type Object struct {
	fs   *Fs
	file *api.File
}

// emptyReader is an io.Reader that always returns the io.EOF error.
type emptyReader struct{}

// Read implements io.Reader for emptyReader, always returning (0, io.EOF).
func (*emptyReader) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

// shouldRetry checks if a failed action should be retried based on the current
// state of the context and the error the failure generated.
func shouldRetry(ctx context.Context, err error) (bool, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	return fserrors.ShouldRetry(err), err
}

// pathParse joins multiple path elements into a single path and removes
// leading/trailing slashes.
//	pathParse("/foo/bar//baz/") == "foo/bar/baz"
//	pathParse("foo/", "/bar") == "foo/bar"
//	pathParse("baz", "quux", "x/y/z") == "baz/quux/x/y/z"
func pathParse(parts ...string) string {
	return strings.Trim(path.Join(parts...), "/")
}

// pathParent returns the directory path of pathChild, similar to the dirname
// UNIX command. Note that pathChild should have no leading/trailing slashes.
//	pathParent("foo/bar") == "foo"
//	pathParent("foo") == ""
//	pathParent("") == ""
func pathParent(pathChild string) string {
	if pathChild == "" {
		return ""
	}
	if pathParent := path.Dir(pathChild); pathParent != "." {
		return pathParent
	}
	return ""
}

// pathRelative returns the relative path from pathFrom to pathTo. Note that
// both pathFrom and pathTo should have no leading/trailing slashes.
//	pathRelative("foo/bar/baz/quux", "foo/bar") == "baz/quux"
//	pathRelative("some/path/somewhere", "another/path") == "some/path/somewhere"
//	pathRelative("foo", "foo") == "foo"
//	pathRelative("foo/", "foo") == ""
func pathRelative(pathFrom, pathTo string) string {
	if pathFrom == "" {
		return ""
	}
	if pathTo == "" {
		return pathFrom
	}
	return strings.TrimPrefix(pathFrom, pathTo+"/")
}

// authBasic returns a valid HTTP "Authorization" header value for "Basic"
// authentication with the given username and password as specified by
// https://datatracker.ietf.org/doc/html/rfc7617. Similar to
// (*http.Request).SetBasicAuth.
func authBasic(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// authBearer returns a valid HTTP "Authorization" header value for "Bearer"
// authentication with the given bearer token.
func authBearer(token string) string {
	return "Bearer " + token
}

// withParams sets the body of the given request to the given URL values
// encoded as "application/x-www-form-urlencoded" as well as setting the
// "Content-Type" and "Content-Length" headers.
func withParams(req *http.Request, values url.Values) {
	if values == nil {
		return
	}
	body := []byte(values.Encode())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
}

// withOptions adds the headers provided by the given opions to the given
// request.
func withOptions(req *http.Request, opts []fs.OpenOption) {
	if opts == nil {
		return
	}
	for _, opt := range opts {
		k, v := opt.Header()
		if v != "" && k != "" {
			req.Header.Add(k, v)
		}
	}
}

// readBody reads the body of the given response, closes it, and then returns
// the body as a byte array.
func readBody(res *http.Response) ([]byte, error) {
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if err := res.Body.Close(); err != nil {
		return nil, err
	}
	return b, nil
}

// sendRequest sends the given request then reads and decodes the response body
// into the given result (if not nil). If the result contains an error then it
// will be returned.
func (f *Fs) sendRequest(req *http.Request, result api.ResultLike) error {
	res, err := f.client.Do(req)
	if err != nil {
		return err
	}
	body, err := readBody(res)
	if err != nil {
		return err
	}
	if result == nil {
		result = new(api.Result)
	}
	if err := json.Unmarshal(body, result); err != nil {
		return err
	}
	return result.ToError()
}

// newRequest returns a new request with the given context, method, and url. It
// also sets the "Authorization" header for API authentication.
func (f *Fs) newRequest(ctx context.Context, method string, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", f.auth)
	return req, nil
}

// apiKey calls the https://neocities.org/api/key API method and returns the
// generated API key string.
func (f *Fs) apiKey(ctx context.Context) (string, error) {
	var out string
	var err = f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "GET", "https://neocities.org/api/key")
		if err != nil {
			return shouldRetry(ctx, err)
		}
		res := new(struct {
			api.Result
			Key string `json:"api_key"`
		})
		if err := f.sendRequest(req, res); err != nil {
			return shouldRetry(ctx, err)
		}
		out = res.Key
		return false, nil
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

// apiInfo calls the https://neocities.org/api/info API method and returns the
// site info object.
func (f *Fs) apiInfo(ctx context.Context) (*api.Site, error) {
	var out *api.Site
	var err = f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "GET", "https://neocities.org/api/info")
		if err != nil {
			return shouldRetry(ctx, err)
		}
		res := new(struct {
			api.Result
			Info *api.Site `json:"info"`
		})
		if err := f.sendRequest(req, res); err != nil {
			return shouldRetry(ctx, err)
		}
		out = res.Info
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// apiInfo calls the https://neocities.org/api/list API method with the
// given path and returns the list of files.
func (f *Fs) apiList(ctx context.Context, path string) ([]*api.File, error) {
	var out []*api.File
	var err = f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "GET", "https://neocities.org/api/list")
		if err != nil {
			return shouldRetry(ctx, err)
		}
		withParams(req, url.Values{
			"path": {path},
		})
		res := new(struct {
			api.Result
			Files []*api.File `json:"files"`
		})
		if err := f.sendRequest(req, res); err != nil {
			return shouldRetry(ctx, err)
		}
		out = res.Files
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// apiRename calls the https://neocities.org/api/rename API method with the
// given old and new paths.
func (f *Fs) apiRename(ctx context.Context, pathOld, pathNew string) error {
	return f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "POST", "https://neocities.org/api/rename")
		if err != nil {
			return shouldRetry(ctx, err)
		}
		withParams(req, url.Values{
			"path":     {pathOld},
			"new_path": {pathNew},
		})
		if err := f.sendRequest(req, nil); err != nil {
			return shouldRetry(ctx, err)
		}
		return false, nil
	})
}

// apiDelete calls the https://neocities.org/api/delete API method with the
// given path.
func (f *Fs) apiDelete(ctx context.Context, path string) error {
	return f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "POST", "https://neocities.org/api/delete")
		if err != nil {
			return shouldRetry(ctx, err)
		}
		withParams(req, url.Values{
			"filenames[]": {path},
		})
		if err := f.sendRequest(req, nil); err != nil {
			return shouldRetry(ctx, err)
		}
		return false, nil
	})
}

// apiUpload calls the https://neocities.org/api/upload API method with the
// given path and headers from the given options, then uploads the data from
// the given io.Reader.
func (f *Fs) apiUpload(ctx context.Context, path string, in io.Reader, opts []fs.OpenOption) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	br, bw := io.Pipe()
	mp := multipart.NewWriter(bw)

	go func() {
		defer func() { _ = bw.Close() }()
		defer func() { _ = mp.Close() }()

		p, err := mp.CreateFormFile(path, path)
		if err != nil {
			_ = bw.CloseWithError(err)
			return
		}

		_, err = io.Copy(p, in)
		if err != nil {
			_ = bw.CloseWithError(err)
			return
		}
	}()

	go func() {
		<-ctx.Done()
		_ = bw.CloseWithError(ctx.Err())
		_ = mp.Close()
	}()

	req, err := f.newRequest(ctx, "POST", "https://neocities.org/api/upload")
	if err != nil {
		return err
	}
	withOptions(req, opts)
	req.Header.Set("Content-Type", mp.FormDataContentType())
	req.Body = br
	return f.sendRequest(req, nil)
}

// hostLink returns the URL of a given remote file path.
func (f *Fs) hostLink(path string) *url.URL {
	link := *f.host
	link.Path = path
	return &link
}

// hostDownload downloads the given remote file specified by path with the
// headers from the given options.
func (f *Fs) hostDownload(ctx context.Context, path string, opts []fs.OpenOption) (io.ReadCloser, error) {
	var out io.ReadCloser
	var err = f.pacer.Call(func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", f.hostLink(path).String(), nil)
		if err != nil {
			return shouldRetry(ctx, err)
		}
		withOptions(req, opts)
		res, err := f.client.Do(req)
		if err != nil {
			return shouldRetry(ctx, err)
		}
		out = res.Body
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// cacheLookup returns the file info for the given path from the file info
// cache, or nil if that path is not in the cache. Note that path should have
// no leading/trailing slashes.
func (f *Fs) cacheLookup(path string) *api.File {
	f.cachemu.Lock()
	defer f.cachemu.Unlock()
	return f.cache[path]
}

// cacheInvalidate removes all file info cache entries that are children
// (including indirect children) of the given path, including the file info at
// the given path itself. Note that path should have no leading/trailing
// slashes.
func (f *Fs) cacheInvalidate(path string) {
	f.cachemu.Lock()
	defer f.cachemu.Unlock()
	if len(f.cache) == 0 {
		return
	}
	if path == "" {
		f.cache = make(map[string]*api.File)
		return
	}
	pathPrefix := path + "/"
	for pathCached := range f.cache {
		if strings.HasPrefix(pathCached, pathPrefix) {
			f.cache[pathCached] = nil
		}
	}
	f.cache[path] = nil
}

// cacheUpdate adds all the given files to the file info cache.
func (f *Fs) cacheUpdate(files []*api.File) {
	f.cachemu.Lock()
	defer f.cachemu.Unlock()
	for _, file := range files {
		file.Path = pathParse(file.Path)
		f.cache[file.Path] = file
	}
}

// performList lists files by communicating with the API and updates the cache.
// Note that path should have no leading/trailing slashes.
func (f *Fs) performList(ctx context.Context, path string) ([]*api.File, error) {
	files, err := f.apiList(ctx, "/"+path)
	if err != nil {
		return nil, err
	}
	f.cacheInvalidate(path)
	f.cacheUpdate(files)
	return files, nil
}

// performMkdir creates a new directory by communicating with the API and
// updates the cache. Note that path should have no leading/trailing slashes.
func (f *Fs) performMkdir(ctx context.Context, path string) error {
	f.cacheInvalidate(path)
	// Since the Neocities API doesn't actually provide a way to create
	// directories, we have to use a workaround. Luckly, if you upload a file
	// into a directory that does not exist, the API will also create that
	// directory. We use that functionality here to create an empty directory by
	// first uploading a dummy file into the directory we want to create, then
	// deleting the dummy file, leaving us with a new empty directory!
	pathTemp := pathParse(path, "__dummy__.txt")
	if err := f.apiUpload(ctx, pathTemp, new(emptyReader), nil); err != nil {
		return err
	}
	if err := f.apiDelete(ctx, pathTemp); err != nil {
		return err
	}
	return nil
}

// performRename renames a file by communicating with the API and updates the
// cache. Note that pathOld and pathNew should have no leading/trailing
// slashes.
func (f *Fs) performRename(ctx context.Context, pathOld, pathNew string) error {
	f.cacheInvalidate(pathOld)
	f.cacheInvalidate(pathNew)
	if err := f.apiRename(ctx, pathOld, pathNew); err != nil {
		return err
	}
	return nil
}

// performDelete deletes a file by communicating with the API and updates the
// cache. Note that path should have no leading/trailing slashes.
func (f *Fs) performDelete(ctx context.Context, path string) error {
	f.cacheInvalidate(path)
	if err := f.apiDelete(ctx, path); err != nil {
		return err
	}
	return nil
}

// performUpload uploads (by creating or updating) a file by communicating with
// the API and updates the cache. Note that path should have no
// leading/trailing slashes.
func (f *Fs) performUpload(ctx context.Context, path string, in io.Reader, opts []fs.OpenOption) error {
	f.cacheInvalidate(path)
	if err := f.apiUpload(ctx, path, in, opts); err != nil {
		return err
	}
	return nil
}

// findFile looks up the file info for the given path. It first checks the
// cache, then requests an updated file listing from the API. Note that path
// should have no leading/trailing slashes.
func (f *Fs) findFile(ctx context.Context, path string) (*api.File, error) {
	if path == "" {
		return nil, fs.ErrorIsDir
	}
	if file := f.cacheLookup(path); file != nil {
		return file, nil
	}
	files, err := f.performList(ctx, pathParent(path))
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.Path == path {
			if file.IsDirectory {
				return nil, fs.ErrorIsDir
			}
			return file, nil
		}
	}
	return nil, fs.ErrorObjectNotFound
}

// findObject looks up an object for the given path. Note that path should have
// no leading/trailing slashes.
func (f *Fs) findObject(ctx context.Context, path string) (fs.Object, error) {
	file, err := f.findFile(ctx, path)
	if err != nil {
		return nil, err
	}
	return &Object{f, file}, nil
}

// init registers the Neocities backend with the file system interface.
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "neocities",
		Description: "Neocities",
		Prefix:      "neo",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{
			{
				Hide: fs.OptionHideConfigurator,
				Name: "username",
				Help: "Account username or associated email address.",
			},
			{
				Hide:       fs.OptionHideConfigurator,
				Name:       "password",
				Help:       "Account password.",
				IsPassword: true,
			},
			{
				Hide:       fs.OptionHideConfigurator,
				Name:       "api_key",
				Help:       "Neocities API key.",
				IsPassword: true,
			},
		},
	})
}

// Config generates the next state of the configuration wizard for the
// Neocities backend.
func Config(ctx context.Context, name string, m configmap.Mapper, config fs.ConfigIn) (*fs.ConfigOut, error) {
	switch config.State {
	case "":
		return fs.ConfigGoto("type")

	case "done":
		return nil, nil

	case "type":
		return fs.ConfigChooseFixed("type_end", "config_auth_type", "Authentication type.",
			[]fs.OptionExample{
				{
					Value: "user_and_pass",
					Help:  "Username (or email) and password authentication.",
				},
				{
					Value: "api_key",
					Help:  "API key/token authentication. See: https://neocities.org/api.",
				},
			},
		)

	case "type_end":
		if config.Result == "user_and_pass" {
			return fs.ConfigGoto("user")
		}
		if config.Result == "api_key" {
			return fs.ConfigGoto("key")
		}

	case "user":
		return fs.ConfigInputOptional("user_end", "config_username", "Account username or associated email address.")

	case "user_end":
		m.Set("username", config.Result)
		return fs.ConfigGoto("pass")

	case "pass":
		return fs.ConfigPassword("pass_end", "config_password", "Account password.")

	case "pass_end":
		m.Set("password", config.Result)
		return fs.ConfigGoto("done")

	case "key":
		return fs.ConfigInput("key_end", "config_api_key", "Neocities API key.")

	case "key_end":
		m.Set("api_key", obscure.MustObscure(config.Result))
		return fs.ConfigGoto("done")
	}

	return nil, fmt.Errorf("unknown state %q", config.State)
}

// NewFs creates a new instance of the Neocities backend. This new remote will
// use the given name, root, and config.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	f := &Fs{
		name:   name,
		root:   root,
		pacer:  fs.NewPacer(ctx, pacer.NewDefault()),
		client: fshttp.NewClient(ctx),
		cache:  make(map[string]*api.File),
	}

	options := new(Options)
	if err := configstruct.Set(m, options); err != nil {
		return nil, err
	}

	features := &fs.Features{
		CanHaveEmptyDirectories: true,
		Move:                    f.Move,
		DirMove:                 f.DirMove,
		PublicLink:              f.PublicLink,
		PutStream:               f.PutStream,
		UserInfo:                f.UserInfo,
	}

	f.options = options
	f.features = features

	if options.APIKey != "" {
		key, err := obscure.Reveal(options.APIKey)
		if err != nil {
			return nil, err
		}
		f.auth = authBearer(key)
	} else {
		user := options.Username
		pass, err := obscure.Reveal(options.Password)
		if err != nil {
			return nil, err
		}
		f.auth = authBasic(user, pass)
		// Since it is much faster to use API keys than usernames/passwords we
		// generate and use a new API key instead of sticking with basic
		// authentication.
		key, err := f.apiKey(ctx)
		if err != nil {
			return nil, err
		}
		f.auth = authBearer(key)
	}

	site, err := f.apiInfo(ctx)
	if err != nil {
		return nil, err
	}

	if site.Domain == "" {
		f.host = &url.URL{
			Scheme: "https",
			Host:   site.Name + ".neocities.org",
		}
	} else {
		f.host = &url.URL{
			Scheme: "https",
			Host:   site.Domain,
		}
	}

	f.site = site

	return f, nil
}

// Name returns the name of the remote as given to NewFs.
func (f *Fs) Name() string {
	return f.name
}

// Root returns the root of the remote as given to NewFs.
func (f *Fs) Root() string {
	return f.root
}

// String returns a human readable description of this Fs.
func (f *Fs) String() string {
	return fmt.Sprintf("neocities root '%s'", f.root)
}

// Features returns the optional features of this FS.
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision returns the precision of timestamps provided by this Fs.
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns a set of this Fs' supported hashing algorithms. Currently
// unsupported.
func (f *Fs) Hashes() hash.Set {
	// Broken due to bug with the Neocities API, see this pull request:
	// https://github.com/neocities/neocities/pull/385
	/*
	return hash.Set(hash.SHA1)
	*/
	return hash.Set(hash.None)
}

// NewObject finds and creates a new object for the given path.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.findObject(ctx, pathParse(f.root, remote))
}

// List returns a list of objects and subdirectories in the directory at the
// given path.
func (f *Fs) List(ctx context.Context, remote string) (fs.DirEntries, error) {
	pathRoot := pathParse(f.root)
	path := pathParse(pathRoot, remote)

	files, err := f.performList(ctx, path)
	if err != nil {
		return nil, err
	}

	entries := make(fs.DirEntries, 0)
	for _, file := range files {
		// Sanity checks incase the API decides to give us files that are not
		// direct children the directory we specified. This can happen eg. if
		// no "path" param is specified. Currently these checks are disabled.
		/*
		if pathParent(file.Path) != path {
			continue
		}
		if strings.ContainsRune(pathRelative(file.Path, path), '/') {
			continue
		}
		*/
		var entry fs.DirEntry
		if file.IsDirectory {
			entry = fs.NewDir(pathRelative(file.Path, pathRoot), time.Time(file.Updated))
		} else {
			entry = &Object{f, file}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Mkdir creates a directory at the given path.
func (f *Fs) Mkdir(ctx context.Context, remote string) error {
	return f.performMkdir(ctx, pathParse(f.root, remote))
}

// Mkdir deletes the directory at the given path.
func (f *Fs) Rmdir(ctx context.Context, remote string) error {
	return f.performDelete(ctx, pathParse(f.root, remote))
}

// Put uploads an object to the given path with the given data and options.
func (f *Fs) Put(ctx context.Context, data io.Reader, src fs.ObjectInfo, opts ...fs.OpenOption) (fs.Object, error) {
	path := pathParse(f.root, src.Remote())
	if err := f.performUpload(ctx, path, data, opts); err != nil {
		return nil, err
	}
	return f.findObject(ctx, path)
}

// PutStream uploads an object to the given path with the given data and options.
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.Put(ctx, in, src, options...)
}

// Move renames an object, potentially moving it to a different directory.
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok || srcObj == nil {
		return nil, fs.ErrorCantMove
	}
	if srcObj.fs.site.Name != f.site.Name {
		return nil, fs.ErrorCantMove
	}

	pathSrc := srcObj.file.Path
	pathDst := pathParse(f.root, remote)

	if err := f.performRename(ctx, pathSrc, pathDst); err != nil {
		return nil, err
	}
	return f.findObject(ctx, pathDst)
}

// DirMove renames a directory, potentially moving it to a different parent
// directory.
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, remoteSrc, remoteDst string) error {
	dstFs := f
	srcFs, ok := src.(*Fs)
	if !ok || srcFs == nil {
		return fs.ErrorCantDirMove
	}
	if srcFs.site.Name != dstFs.site.Name {
		return fs.ErrorCantDirMove
	}
	return f.performRename(ctx,
		pathParse(srcFs.root, remoteSrc),
		pathParse(dstFs.root, remoteDst),
	)
}

// PublicLink gets the URL of a remote object (provided by the given path).
// Note that the expire and unlink arguments are ignored, files on Neocities
// are always public on the web.
func (f *Fs) PublicLink(ctx context.Context, remote string, expire fs.Duration, unlink bool) (string, error) {
	return f.hostLink(pathParse(f.root, remote)).String(), nil
}

// UserInfo returns some basic information about the current user and their
// site. See the following example:
//	{
//		"site": "mycoolsite",
//		"tags": "super, awesome, cool, nice",
//		"domain": "mycoolsite.neocities.org"
//	}
func (f *Fs) UserInfo(ctx context.Context) (map[string]string, error) {
	return map[string]string{
		"site":   f.site.Name,
		"tags":   strings.Join(f.site.Tags, ", "),
		"domain": f.host.String(),
	}, nil
}

// Fs returns the parent Fs instance of this object.
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Remote returns the remote path of this object.
func (o *Object) Remote() string {
	return pathRelative(o.file.Path, pathParse(o.fs.root))
}

// String returns a human readable description of this object.
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.Remote()
}

// ModTime returns the last modified timestamp of this object.
func (o *Object) ModTime(ctx context.Context) time.Time {
	return time.Time(o.file.Updated)
}

// Size returns the size of this object in bytes.
func (o *Object) Size() int64 {
	return o.file.Size
}

// Storable returns true if this object can be stored, false otherwise.
func (o *Object) Storable() bool {
	return true
}

// Hash returns the hash of this object. Currently unsupported.
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	// Broken due to bug with the Neocities API, see this pull request:
	// https://github.com/neocities/neocities/pull/385
	/*
	if o.file.Sha1Hash == "" {
		return "", hash.ErrUnsupported
	}
	if o.file.IsDirectory {
		return "", fs.ErrorIsDir
	}
	return o.file.Sha1Hash, nil
	*/
	return "", hash.ErrUnsupported
}

// SetModTime is not supported.
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

// Open downloads this object from the remote host.
func (o *Object) Open(ctx context.Context, opts ...fs.OpenOption) (io.ReadCloser, error) {
	return o.fs.hostDownload(ctx, o.file.Path, opts)
}

// Remove deletes this object.
func (o *Object) Remove(ctx context.Context) error {
	err := o.fs.performDelete(ctx, o.file.Path)
	// Ignore errors from trying to delete an object that no longer exists.
	if apiErr, ok := err.(*api.Error); ok && apiErr != nil && apiErr.Kind == "missing_files" {
		return nil
	}
	return err
}

// Update overwrites this object with the given data and options.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, opts ...fs.OpenOption) error {
	err := o.fs.performUpload(ctx, o.file.Path, in, opts)
	if err != nil {
		return err
	}
	file, err := o.fs.findFile(ctx, o.file.Path)
	if err != nil {
		return err
	}
	o.file = file
	return nil
}
