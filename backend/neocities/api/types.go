package api

import (
	"fmt"
	"time"
)

// timeFormat is the JSON-quoted Ruby Date#rfc2822 time format.
const timeFormat = `"Mon, 02 Jan 2006 15:04:05 -0700"`

// Timestamp represents a timestamp returned from the Neocities API.
type Timestamp time.Time

// MarshalJSON encodes a Timestamp into a JSON string.
func (ts *Timestamp) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(timeFormat)), nil
}

// UnmarshalJSON decodes a Timestamp from a JSON string.
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

// Site is returned from a request to https://neocities.org/api/info.
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

// File is an element of the JSON array returned from a request to
// https://neocities.org/api/list.
type File struct {
	Path        string    `json:"path"`
	IsDirectory bool      `json:"is_directory"`
	Updated     Timestamp `json:"updated_at"`
	Size        int64     `json:"size"`
	Sha1Hash    string    `json:"sha1_hash"`
}

// Error represents an error returned from an API request.
type Error struct {
	Kind    string
	Message string
}

// Error implements the error interface, returning a string with the error kind
// and message.
func (e *Error) Error() string {
	return fmt.Sprintf("api error '%s': %s", e.Kind, e.Message)
}

// Result represents the basic structure of any given result returned from an
// API request.
type Result struct {
	Status    string `json:"result"`
	Message   string `json:"message"`
	ErrorType string `json:"error_type"`
}

// ResultLike describes an object that may contain an API error.
type ResultLike interface {
	ToError() error
}

// ToError implements the ResultLike interface, checking the Status of the
// result and returning an error as appropriate.
func (r *Result) ToError() error {
	if r.Status == "success" {
		return nil
	}
	if r.ErrorType == "" {
		return &Error{"unknown", "unknown api error"}
	}
	return &Error{r.ErrorType, r.Message}
}
