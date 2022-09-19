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
	response.Title = MatchTitle(string(response.RawContent))
	response.Server = resp.Header.Get("Server")
	response.Language = MatchLanguageWithRaw(string(response.HeaderContent))
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
	response.Title = MatchTitle(string(response.RawContent))
	response.Server, _ = MatchOne(ServerRegexp, string(response.HeaderContent))
	response.Language = MatchLanguageWithRaw(string(response.HeaderContent))
	return response
}

type Response struct {
	*http.Response
	SSLHost       []string
	BodyContent   []byte
	HeaderContent []byte
	RawContent    []byte
	Language      string
	Server        string
	Title         string
	*Hashes
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
	BodyMd5       string
	HeaderMd5     string
	RawMd5        string
	BodySimhash   string
	HeaderSimhash string
	RawSimhash    string
	BodyMmh3      string
}
