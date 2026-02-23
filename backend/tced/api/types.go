// Package api has type definitions for Tencent Cloud Enterprise Drive.
package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

const (
	// ItemTypeDir represents a directory item.
	ItemTypeDir = "dir"
	// ItemTypeFile represents a file item.
	ItemTypeFile = "file"
)

// Time is an RFC3339/RFC3339Nano encoded time.
type Time time.Time

// UnmarshalJSON decodes time in RFC3339 or RFC3339Nano format.
func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*t = Time(time.Time{})
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*t = Time(time.Time{})
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return err
		}
	}
	*t = Time(parsed)
	return nil
}

// Value returns this as time.Time.
func (t Time) Value() time.Time {
	return time.Time(t)
}

// Int64 is an integer that may be encoded as JSON string/number/null.
type Int64 int64

// UnmarshalJSON decodes Int64 from string/number/null.
func (i *Int64) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*i = 0
		return nil
	}
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		if asString == "" {
			*i = 0
			return nil
		}
		v, err := strconv.ParseInt(asString, 10, 64)
		if err != nil {
			return err
		}
		*i = Int64(v)
		return nil
	}
	var asInt int64
	if err := json.Unmarshal(data, &asInt); err == nil {
		*i = Int64(asInt)
		return nil
	}
	var asFloat float64
	if err := json.Unmarshal(data, &asFloat); err == nil {
		*i = Int64(asFloat)
		return nil
	}
	return fmt.Errorf("can't decode %q as Int64", string(data))
}

// Value returns this as int64.
func (i Int64) Value() int64 {
	return int64(i)
}

// Error is returned from TCED APIs when things go wrong.
type Error struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error returns string representation and satisfies error interface.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Code == "" && e.Message == "" {
		return fmt.Sprintf("tced error: status=%d", e.Status)
	}
	return fmt.Sprintf("tced error: status=%d code=%q message=%q", e.Status, e.Code, e.Message)
}

// UserTokenResponse is returned by SJTU SSO verification.
type UserTokenResponse struct {
	UserToken string `json:"userToken"`
	ExpiresIn int64  `json:"expiresIn"`
}

// SpaceCredential is returned by /user/v1/space/1/personal.
type SpaceCredential struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int64  `json:"expiresIn"`
	LibraryID   string `json:"libraryId"`
	SpaceID     string `json:"spaceId"`
}

// SpaceInfo is returned by /user/v1/space/1.
type SpaceInfo struct {
	Capacity       Int64 `json:"capacity"`
	Size           Int64 `json:"size"`
	AvailableSpace Int64 `json:"availableSpace"`
}

// ListResult is returned by directory listing API.
type ListResult struct {
	Contents []Item `json:"contents"`
	TotalNum int64  `json:"totalNum"`
}

// Item is a merged file/directory metadata object.
type Item struct {
	Type             string   `json:"type"`
	Name             string   `json:"name"`
	Path             []string `json:"path"`
	ContentType      string   `json:"contentType"`
	Size             Int64    `json:"size"`
	CreationTime     Time     `json:"creationTime"`
	ModificationTime Time     `json:"modificationTime"`
}

// StartSimpleUploadResult contains signed upload information.
type StartSimpleUploadResult struct {
	ConfirmKey string            `json:"confirmKey"`
	Domain     string            `json:"domain"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
}

// CopyMoveRequest is request body for copy/move APIs.
type CopyMoveRequest struct {
	From     string `json:"from,omitempty"`
	CopyFrom string `json:"copyFrom,omitempty"`
}
