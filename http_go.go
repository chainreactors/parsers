//go:build !go1.17
// +build !go1.17

package parsers

import (
	"github.com/chainreactors/utils/encode"
	"net/http"
	"strings"
)

func NewResponse(resp *http.Response) *Response {
	r := &Response{
		Content: NewContent(ReadRaw(resp)),
	}

	if title := MatchTitle(r.Raw); title != "" {
		r.HasTitle = true
		r.Title = title
	} else {
		r.Title = MatchCharacter(r.Raw)
	}
	r.Server = resp.Header.Get("Server")
	r.Language = MatchLanguageWithRaw(r.Header)
	if resp.TLS != nil {
		r.SSLHost = resp.TLS.PeerCertificates[0].DNSNames
	}

	for resp = resp.Request.Response; resp != nil; {
		content := NewContent(ReadRaw(resp))
		if resp.TLS != nil {
			content.SSLHost = resp.TLS.PeerCertificates[0].DNSNames
		}
		r.History = append(r.History, content)
		resp = resp.Request.Response
	}
	return r
}

func NewResponseWithRaw(raw []byte) *Response {
	resp := &Response{
		Content: NewContent(raw),
	}

	if title := MatchTitle(resp.Raw); title != "" {
		resp.HasTitle = true
		resp.Title = title
	} else {
		resp.Title = MatchCharacter(resp.Raw)
	}
	resp.Server, _ = MatchOne(ServerRegexp, resp.Header)
	resp.Language = MatchLanguageWithRaw(resp.Header)

	return resp
}

type Response struct {
	Language string `json:"language"`
	Server   string `json:"server"`
	Title    string `json:"title"`
	HasTitle bool   `json:"-"`
	*Content
	History []*Content `json:"history"`
	*Hashes `json:"hashes"`
}

func NewContent(raw []byte) *Content {
	body, header, _ := SplitHttpRaw(raw)
	return &Content{
		Body:   body,
		Header: header,
		Raw:    raw,
	}
}

type Content struct {
	Body    []byte   `json:"-"`
	Header  []byte   `json:"-"`
	Raw     []byte   `json:"raw"`
	SSLHost []string `json:"sslhsot"`
}

func (content *Content) ContentMap() map[string]interface{} {
	return map[string]interface{}{
		"content": content.Raw,
		"cert":    strings.Join(content.SSLHost, ","),
	}
}

func (r *Response) Hash() {
	r.Hashes = NewHashes(r.Raw)
}

func NewHashes(content []byte) *Hashes {
	body, header, _ := SplitHttpRaw(content)
	return &Hashes{
		BodyMd5:       encode.Md5Hash(body),
		HeaderMd5:     encode.Md5Hash(header),
		RawMd5:        encode.Md5Hash(content),
		BodySimhash:   encode.Simhash(body),
		HeaderSimhash: encode.Simhash(header),
		RawSimhash:    encode.Simhash(content),
		BodyMmh3:      encode.Mmh3Hash32(body),
	}
}

type Hashes struct {
	BodyMd5       string `json:"body-md5"`
	HeaderMd5     string `json:"header-md5"`
	RawMd5        string `json:"raw-md5"`
	BodySimhash   string `json:"body-simhash"`
	HeaderSimhash string `json:"header-simhash"`
	RawSimhash    string `json:"raw-simhash"`
	BodyMmh3      string `json:"body-mmh3"`
}

var SimhashThreshold uint8 = 8

func (hs *Hashes) Compare(other *Hashes) (uint8, uint8, uint8) {
	return encode.SimhashCompare(hs.BodySimhash, other.BodySimhash), encode.SimhashCompare(hs.HeaderSimhash, other.HeaderSimhash), encode.SimhashCompare(hs.RawSimhash, other.RawSimhash)
}
