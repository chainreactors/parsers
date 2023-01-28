package parsers

import (
	"fmt"
	"github.com/chainreactors/parsers/iutils"
	"regexp"
	"strings"
)

type Extracted struct {
	Name          string   `json:"name"`
	ExtractResult []string `json:"extract_result"`
}

func (e *Extracted) String() string {
	if len(e.ExtractResult) == 1 {
		if len(e.ExtractResult[0]) > 30 {
			return fmt.Sprintf("%s:%s ... %d bytes", e.Name, iutils.AsciiEncode(e.ExtractResult[0][:30]), len(e.ExtractResult[0]))
		}
		return fmt.Sprintf("%s:%s", e.Name, iutils.AsciiEncode(e.ExtractResult[0]))
	} else {
		return fmt.Sprintf("%s:%d items", e.Name, len(e.ExtractResult))
	}
}

type Extracteds []*Extracted

func (es Extracteds) String() string {
	var s strings.Builder
	for _, e := range es {
		s.WriteString("[ " + e.String() + " ]")
	}
	return s.String() + " "
}

type Extractor struct {
	Name            string           `json:"name"` // extractor name
	Regexps         []string         `json:"regexps"`
	Tags            []string         `json:"tags"`
	CompiledRegexps []*regexp.Regexp `json:"-"`
}

func (e *Extractor) Compile() {
	e.CompiledRegexps = make([]*regexp.Regexp, len(e.Regexps))
	for i, r := range e.Regexps {
		if parsed, ok := DSLParserToString(iutils.ToString(r)); ok {
			e.CompiledRegexps[i] = regexp.MustCompile(parsed)
		} else {
			e.CompiledRegexps[i] = regexp.MustCompile(iutils.ToString(r))
		}
	}
}

func (e *Extractor) HasTag(tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (e *Extractor) Extract(body string) *Extracted {
	extracts := &Extracted{
		Name: e.Name,
	}
	for _, r := range e.CompiledRegexps {
		matches := r.FindAllString(body, -1)
		extracts.ExtractResult = append(extracts.ExtractResult, matches...)
	}
	return extracts
}

type Extractors map[string][]*regexp.Regexp

func (es Extractors) Extract(content string) (extracts []*Extracted) {
	if len(content) == 0 {
		return
	}

	for name, regexps := range es {
		extracted := &Extracted{
			Name: name,
		}
		for _, r := range regexps {
			matches := r.FindAllString(content, -1)
			extracted.ExtractResult = append(extracted.ExtractResult, matches...)
		}
		extracts = append(extracts, extracted)
	}
	return extracts
}
