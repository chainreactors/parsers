package parsers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

var (
	TitleRegexp   = regexp.MustCompile("(?Uis)<title>(.*)</title>")
	ServerRegexp  = regexp.MustCompile("(?i)Server: ([\x20-\x7e]+)")
	XPBRegexp     = regexp.MustCompile("(?i)X-Powered-By: ([\x20-\x7e]+)")
	SessionRegexp = regexp.MustCompile("(?i) (.*SESS.*?ID)")
	CharsetRegexp = regexp.MustCompile("(?i)Content-Type:.*charset=(.+)")
)

func MatchOne(reg *regexp.Regexp, s []byte) (string, bool) {
	matched := reg.FindSubmatch(s)
	if len(matched) == 0 {
		return "", false
	}
	if len(matched) == 1 {
		return "", true
	} else {
		return strings.TrimSpace(string(matched[1])), true
	}
}

func SplitHttpRaw(content []byte) (body, header []byte, ok bool) {
	cs := bytes.Index(content, []byte("\r\n\r\n"))
	if cs != -1 && len(content) >= cs+4 {
		body = content[cs+4:]
		header = content[:cs]
		return body, header, true
	}
	return nil, nil, false
}

func ReadRaw(resp *http.Response) []byte {
	var raw string

	raw += fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status)
	for k, v := range resp.Header {
		for _, i := range v {
			raw += fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}
	raw += "\r\n"
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte(raw)
	}
	raw += string(body)
	_ = resp.Body.Close()
	return []byte(raw)
}

func ReadBody(resp *http.Response) []byte {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}
	}
	_ = resp.Body.Close()
	return body
}

func ReadHeader(resp *http.Response) []byte {
	var header string
	for k, v := range resp.Header {
		for _, i := range v {
			header += fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}
	return []byte(header)
}

func MatchCharset(content []byte) string {
	charset, ok := MatchOne(CharsetRegexp, content)
	if ok {
		return charset
	}
	return ""
}

func MatchTitle(content []byte) string {
	title, ok := MatchOne(TitleRegexp, content)
	if ok {
		return title
	}
	return ""
}

func MatchCharacter(content []byte) string {
	if len(content) > 13 {
		return string(content[0:13])
	} else {
		return string(content)
	}
}

func MatchLanguage(resp *http.Response) string {
	var powered string
	powered = resp.Header.Get("X-Powered-By")
	if powered != "" {
		return powered
	}

	cookies := getCookies(resp)
	if cookies["JSESSIONID"] != "" {
		return "JAVA"
	} else if cookies["ASP.NET_SessionId"] != "" {
		return "ASP"
	} else if cookies["PHPSESSID"] != "" {
		return "PHP"
	} else {
		return ""
	}
}

func MatchLanguageWithRaw(content []byte) string {
	powered, ok := MatchOne(XPBRegexp, content)
	if ok {
		return powered
	}

	sessionid, ok := MatchOne(SessionRegexp, content)
	if ok {
		switch sessionid {
		case "JSESSIONID":
			return "JAVA"
		case "ASP.NET_SessionId":
			return "ASP.NET"
		case "PHPSESSID":
			return "PHP"
		}
	}
	return ""
}

func getCookies(resp *http.Response) map[string]string {
	cookies := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	return cookies
}

func slashComma(s string) string {
	return strings.Replace(s, ",", "\\,", -1)
}

func notContains(s, substr string) bool {
	return !strings.Contains(s, substr)
}

func notEqualFlod(s, substr string) bool {
	return !strings.EqualFold(s, substr)
}
