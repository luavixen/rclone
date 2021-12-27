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

type Options struct {
	Username string `config:"username"`
	Password string `config:"password"`
	APIKey   string `config:"api_key"`
}

type Fs struct {
	name     string
	root     string
	options  *Options
	features *fs.Features
	pacer    *fs.Pacer
	client   *http.Client
	auth     string
	host     *url.URL
	site     *api.Site
	cachemu  sync.Mutex
	cache    map[string]*api.File
}

type Object struct {
	fs   *Fs
	file *api.File
}

type emptyReader struct{}

func (*emptyReader) Read(_ []byte) (int, error) { return 0, io.EOF }

func shouldRetry(err error) bool {
	return fserrors.ShouldRetry(err)
}

func pathParse(parts ...string) string {
	return strings.Trim(path.Join(parts...), "/")
}

func pathParent(pathChild string) string {
	if pathChild == "" {
		return ""
	}
	if pathParent := path.Dir(pathChild); pathParent != "." {
		return pathParent
	}
	return ""
}

func pathRelative(pathFrom, pathTo string) string {
	if pathFrom == "" {
		return ""
	}
	if pathTo == "" {
		return pathFrom
	}
	return strings.TrimPrefix(pathFrom, pathTo+"/")
}

func authBasic(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func authBearer(token string) string {
	return "Bearer " + token
}

func withParams(req *http.Request, values url.Values) {
	if values == nil {
		return
	}
	body := []byte(values.Encode())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
}

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

func readBody(res *http.Response) ([]byte, error) {
	defer res.Body.Close()
	return ioutil.ReadAll(res.Body)
}

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

func (f *Fs) newRequest(ctx context.Context, method string, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", f.auth)
	return req, nil
}

func (f *Fs) apiKey(ctx context.Context) (string, error) {
	var out string
	var err = f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "GET", "https://neocities.org/api/key")
		if err != nil {
			return shouldRetry(err), err
		}
		res := new(struct {
			api.Result
			Key string `json:"api_key"`
		})
		if err := f.sendRequest(req, res); err != nil {
			return shouldRetry(err), err
		}
		out = res.Key
		return false, nil
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

func (f *Fs) apiInfo(ctx context.Context) (*api.Site, error) {
	var out *api.Site
	var err = f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "GET", "https://neocities.org/api/info")
		if err != nil {
			return shouldRetry(err), err
		}
		res := new(struct {
			api.Result
			Info *api.Site `json:"info"`
		})
		if err := f.sendRequest(req, res); err != nil {
			return shouldRetry(err), err
		}
		out = res.Info
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (f *Fs) apiList(ctx context.Context, path string) ([]*api.File, error) {
	var out []*api.File
	var err = f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "GET", "https://neocities.org/api/list")
		if err != nil {
			return shouldRetry(err), err
		}
		withParams(req, url.Values{
			"path": {path},
		})
		res := new(struct {
			api.Result
			Files []*api.File `json:"files"`
		})
		if err := f.sendRequest(req, res); err != nil {
			return shouldRetry(err), err
		}
		out = res.Files
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (f *Fs) apiRename(ctx context.Context, pathOld, pathNew string) error {
	return f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "POST", "https://neocities.org/api/rename")
		if err != nil {
			return shouldRetry(err), err
		}
		withParams(req, url.Values{
			"path":     {pathOld},
			"new_path": {pathNew},
		})
		if err := f.sendRequest(req, nil); err != nil {
			return shouldRetry(err), err
		}
		return false, nil
	})
}

func (f *Fs) apiDelete(ctx context.Context, path string) error {
	return f.pacer.Call(func() (bool, error) {
		req, err := f.newRequest(ctx, "POST", "https://neocities.org/api/delete")
		if err != nil {
			return shouldRetry(err), err
		}
		withParams(req, url.Values{
			"filenames[]": {path},
		})
		if err := f.sendRequest(req, nil); err != nil {
			return shouldRetry(err), err
		}
		return false, nil
	})
}

func (f *Fs) apiUpload(ctx context.Context, path string, in io.Reader, opts []fs.OpenOption) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	br, bw := io.Pipe()
	mp := multipart.NewWriter(bw)

	go func() {
		defer bw.Close()
		defer mp.Close()

		p, err := mp.CreateFormFile(path, path)
		if err != nil {
			bw.CloseWithError(err)
			return
		}

		_, err = io.Copy(p, in)
		if err != nil {
			bw.CloseWithError(err)
			return
		}
	}()

	go func() {
		<-ctx.Done()
		bw.CloseWithError(ctx.Err())
		mp.Close()
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

func (f *Fs) hostLink(path string) *url.URL {
	link := *f.host
	link.Path = path
	return &link
}

func (f *Fs) hostDownload(ctx context.Context, path string, opts []fs.OpenOption) (io.ReadCloser, error) {
	var out io.ReadCloser
	var err = f.pacer.Call(func() (bool, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", f.hostLink(path).String(), nil)
		if err != nil {
			return shouldRetry(err), err
		}
		withOptions(req, opts)
		res, err := f.client.Do(req)
		if err != nil {
			return shouldRetry(err), err
		}
		out = res.Body
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (f *Fs) cacheLookup(path string) *api.File {
	f.cachemu.Lock()
	defer f.cachemu.Unlock()
	return f.cache[path]
}

func (f *Fs) cacheInvalidate(pathDir string) {
	f.cachemu.Lock()
	defer f.cachemu.Unlock()
	if len(f.cache) == 0 {
		return
	}
	if pathDir == "" {
		f.cache = make(map[string]*api.File)
		return
	}
	pathPrefix := pathDir + "/"
	for path := range f.cache {
		if strings.HasPrefix(path, pathPrefix) {
			f.cache[path] = nil
		}
	}
}

func (f *Fs) performList(ctx context.Context, path string) ([]*api.File, error) {
	files, err := f.apiList(ctx, "/"+path)
	if err != nil {
		return nil, err
	}
	f.cacheInvalidate(path)
	f.cachemu.Lock()
	defer f.cachemu.Unlock()
	for _, file := range files {
		file.Path = pathParse(file.Path)
		f.cache[file.Path] = file
	}
	return files, nil
}

func (f *Fs) performMkdir(ctx context.Context, path string) error {
	pathTemp := pathParse(path, "__dummy__.txt")
	if err := f.apiUpload(ctx, pathTemp, new(emptyReader), nil); err != nil {
		return err
	}
	if err := f.apiDelete(ctx, pathTemp); err != nil {
		return err
	}
	f.cacheInvalidate(pathParent(path))
	return nil
}

func (f *Fs) performRename(ctx context.Context, pathOld, pathNew string) error {
	if err := f.apiRename(ctx, pathOld, pathNew); err != nil {
		return err
	}
	pathOldParent := pathParent(pathOld)
	pathNewParent := pathParent(pathNew)
	f.cacheInvalidate(pathOldParent)
	if pathOldParent != pathNewParent {
		f.cacheInvalidate(pathNewParent)
	}
	return nil
}

func (f *Fs) performDelete(ctx context.Context, path string) error {
	if err := f.apiDelete(ctx, path); err != nil {
		return err
	}
	f.cacheInvalidate(pathParent(path))
	return nil
}

func (f *Fs) performUpload(ctx context.Context, path string, in io.Reader, opts []fs.OpenOption) error {
	if err := f.apiUpload(ctx, path, in, opts); err != nil {
		return err
	}
	f.cacheInvalidate(pathParent(path))
	return nil
}

func (f *Fs) findObject(ctx context.Context, path string) (fs.Object, error) {
	if path == "" {
		return nil, fs.ErrorIsDir
	}
	if file := f.cacheLookup(path); file != nil {
		if file.IsDirectory {
			return nil, fs.ErrorIsDir
		}
		return &Object{f, file}, nil
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
			return &Object{f, file}, nil
		}
	}
	return nil, fs.ErrorObjectNotFound
}

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
			},
			{
				Hide:       fs.OptionHideConfigurator,
				Name:       "password",
				IsPassword: true,
			},
			{
				Hide:       fs.OptionHideConfigurator,
				Name:       "api_key",
				IsPassword: true,
			},
		},
	})
}

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
					Help:  "API key/token authentication. See: https://neocities.org/api",
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

	if site.Domain != "" {
		f.host = &url.URL{
			Scheme: "https",
			Host:   site.Domain,
		}
	} else {
		f.host = &url.URL{
			Scheme: "https",
			Host:   site.Name + ".neocities.org",
		}
	}

	f.site = site

	return f, nil
}

func (f *Fs) Name() string {
	return f.name
}

func (f *Fs) Root() string {
	return f.root
}

func (f *Fs) String() string {
	return fmt.Sprintf("neocities root '%s'", f.root)
}

func (f *Fs) Precision() time.Duration {
	return time.Second
}

func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

func (f *Fs) Features() *fs.Features {
	return f.features
}

func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.findObject(ctx, pathParse(f.root, remote))
}

func (f *Fs) List(ctx context.Context, remote string) (fs.DirEntries, error) {
	pathRoot := pathParse(f.root)
	path := pathParse(pathRoot, remote)

	files, err := f.performList(ctx, path)
	if err != nil {
		return nil, err
	}

	entries := make(fs.DirEntries, 0)
	for _, file := range files {
		if pathParent(file.Path) != path {
			continue
		}
		if strings.ContainsRune(pathRelative(file.Path, path), '/') {
			continue
		}
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

func (f *Fs) Mkdir(ctx context.Context, remote string) error {
	return f.performMkdir(ctx, pathParse(f.root, remote))
}

func (f *Fs) Rmdir(ctx context.Context, remote string) error {
	return f.performDelete(ctx, pathParse(f.root, remote))
}

func (f *Fs) Put(ctx context.Context, data io.Reader, src fs.ObjectInfo, opts ...fs.OpenOption) (fs.Object, error) {
	path := pathParse(f.root, src.Remote())
	if err := f.performUpload(ctx, path, data, opts); err != nil {
		return nil, err
	}
	return f.findObject(ctx, path)
}

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

func (f *Fs) PublicLink(ctx context.Context, remote string, expire fs.Duration, unlink bool) (string, error) {
	return f.hostLink(pathParse(f.root, remote)).String(), nil
}

func (f *Fs) UserInfo(ctx context.Context) (map[string]string, error) {
	return map[string]string{
		"site":   f.site.Name,
		"tags":   strings.Join(f.site.Tags, ", "),
		"domain": f.host.String(),
	}, nil
}

func (o *Object) Fs() fs.Info {
	return o.fs
}

func (o *Object) Remote() string {
	return pathRelative(o.file.Path, pathParse(o.fs.root))
}

func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.Remote()
}

func (o *Object) ModTime(ctx context.Context) time.Time {
	return time.Time(o.file.Updated)
}

func (o *Object) Size() int64 {
	return o.file.Size
}

func (o *Object) Storable() bool {
	return o.file.IsDirectory
}

func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

func (o *Object) Open(ctx context.Context, opts ...fs.OpenOption) (io.ReadCloser, error) {
	return o.fs.hostDownload(ctx, o.file.Path, opts)
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, opts ...fs.OpenOption) error {
	return o.fs.performUpload(ctx, o.file.Path, in, opts)
}

func (o *Object) Remove(ctx context.Context) error {
	return o.fs.performDelete(ctx, o.file.Path)
}
