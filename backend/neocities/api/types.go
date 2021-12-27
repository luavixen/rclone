package api

import (
	"fmt"
	"time"
)

const timeFormat = `"Mon, 02 Jan 2006 15:04:05 -0700"`

type Timestamp time.Time

func (ts *Timestamp) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(timeFormat)), nil
}

func (ts *Timestamp) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "" || s == "null" {
		*ts = Timestamp(time.Now())
		return nil
	}
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return err
	}
	*ts = Timestamp(t)
	return nil
}

type Site struct {
	Name         string    `json:"sitename"`
	Domain       string    `json:"domain"`
	Tags         []string  `json:"tags"`
	IpfsHash     string    `json:"latest_ipfs_hash"`
	Created      Timestamp `json:"created_at"`
	Updated      Timestamp `json:"last_updated"`
	PageViews    int64     `json:"hits"`
	ProfileViews int64     `json:"views"`
}

type File struct {
	Path        string    `json:"path"`
	IsDirectory bool      `json:"is_directory"`
	Updated     Timestamp `json:"updated_at"`
	Size        int64     `json:"size"`
	Sha1Hash    string    `json:"sha1_hash"`
}

type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("api error '%s': %s", e.Kind, e.Message)
}

type Result struct {
	Status    string `json:"result"`
	Message   string `json:"message"`
	ErrorType string `json:"error_type"`
}

type ResultLike interface {
	ToError() error
}

func (r *Result) ToError() error {
	if r.Status == "success" {
		return nil
	}
	if r.ErrorType == "" {
		return &Error{"unknown", "unknown api error"}
	}
	return &Error{r.ErrorType, r.Message}
}
