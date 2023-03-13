package parsers

import (
	"net/http"
)

func NewResponse(resp *http.Response) *Response {
	response := &Response{
		Response:   resp,
		RawContent: ReadRaw(resp),
	}

	response.BodyContent, response.HeaderContent, _ = SplitHttpRaw(response.RawContent)
	response.Title = MatchTitle(response.RawContent)
	response.Server = resp.Header.Get("Server")
	response.Language = MatchLanguageWithRaw(response.HeaderContent)
	if resp.TLS != nil {
		response.SSLHost = resp.TLS.PeerCertificates[0].DNSNames
	}
	return response
}

func NewResponseWithRaw(raw []byte) *Response {
	response := &Response{
		RawContent: raw,
	}
	response.BodyContent, response.HeaderContent, _ = SplitHttpRaw(response.RawContent)
	response.Title = MatchTitle(response.RawContent)
	response.Server, _ = MatchOne(ServerRegexp, response.HeaderContent)
	response.Language = MatchLanguageWithRaw(response.HeaderContent)
	return response
}

type Response struct {
	*http.Response `json:"-"`
	SSLHost        []string `json:"sslhsot"`
	BodyContent    []byte   `json:"-"`
	HeaderContent  []byte   `json:"-"`
	RawContent     []byte   `json:"raw"`
	Language       string   `json:"language"`
	Server         string   `json:"server"`
	Title          string   `json:"title"`
	*Hashes        `json:"hashes"`
}

func (r *Response) Hash() {
	r.Hashes = NewHashes(r.RawContent)
}

func NewHashes(content []byte) *Hashes {
	body, header, _ := SplitHttpRaw(content)
	return &Hashes{
		BodyMd5:       Md5Hash(body),
		HeaderMd5:     Md5Hash(header),
		RawMd5:        Md5Hash(content),
		BodySimhash:   Simhash(body),
		HeaderSimhash: Simhash(header),
		RawSimhash:    Simhash(content),
		BodyMmh3:      Mmh3Hash32(body),
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
	return SimhashCompare(hs.BodySimhash, other.BodySimhash), SimhashCompare(hs.HeaderSimhash, other.HeaderSimhash), SimhashCompare(hs.RawSimhash, other.RawSimhash)
}
