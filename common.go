package parsers

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	FrameFromDefault = iota
	FrameFromACTIVE
	FrameFromICO
	FrameFromNOTFOUND
	FrameFromGUESS
)

var NoGuess bool
var frameFromMap = map[int]string{
	FrameFromDefault:  "finger",
	FrameFromACTIVE:   "active",
	FrameFromICO:      "ico",
	FrameFromNOTFOUND: "404",
	FrameFromGUESS:    "guess",
}

func GetFrameFrom(s string) int {
	switch s {
	case "active":
		return FrameFromACTIVE
	case "404":
		return FrameFromNOTFOUND
	case "ico":
		return FrameFromICO
	case "guess":
		return FrameFromGUESS
	default:
		return FrameFromDefault
	}
}

type Framework struct {
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"`
	From    int          `json:"-"`
	Froms   map[int]bool `json:"froms,omitempty"`
	Tags    []string     `json:"tags,omitempty"`
	IsFocus bool         `json:"is_focus,omitempty"`
	Data    string       `json:"-"`
}

func (f *Framework) String() string {
	var s strings.Builder
	if f.IsFocus {
		s.WriteString("focus:")
	}
	s.WriteString(f.Name)

	if f.Version != "" {
		s.WriteString(":" + strings.Replace(f.Version, ":", "_", -1))
	}

	if len(f.Froms) > 1 {
		s.WriteString(":")
		for from, _ := range f.Froms {
			s.WriteString(frameFromMap[from] + " ")
		}
	} else {
		for from, _ := range f.Froms {
			if from != FrameFromDefault {
				s.WriteString(":")
				s.WriteString(frameFromMap[from])
			}
		}
	}
	return strings.TrimSpace(s.String())
}

func (f *Framework) IsGuess() bool {
	var is bool
	for from, _ := range f.Froms {
		if from == FrameFromGUESS {
			is = true
		} else {
			return false
		}
	}
	return is
}

func (f *Framework) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

type Frameworks map[string]*Framework

func (fs Frameworks) Add(other *Framework) {
	if frame, ok := fs[other.Name]; ok {
		frame.Froms[other.From] = true
	} else {
		other.Froms = map[int]bool{other.From: true}
		fs[other.Name] = other
	}
}

func (fs Frameworks) String() string {
	if fs == nil {
		return ""
	}
	var frameworkStrs []string
	for _, f := range fs {
		if NoGuess && f.IsGuess() {
			continue
		}
		frameworkStrs = append(frameworkStrs, f.String())
	}
	return strings.Join(frameworkStrs, "||")
}

func (fs Frameworks) GetNames() []string {
	if fs == nil {
		return nil
	}
	var titles []string
	for _, f := range fs {
		if !f.IsGuess() {
			titles = append(titles, f.Name)
		}
	}
	return titles
}

func (fs Frameworks) IsFocus() bool {
	if fs == nil {
		return false
	}
	for _, f := range fs {
		if f.IsFocus {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasTag(tag string) bool {
	for _, f := range fs {
		if f.HasTag(tag) {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasFrom(from string) bool {
	for _, f := range fs {
		if f.Froms[GetFrameFrom(from)] {
			return true
		}
	}
	return false
}

const (
	SeverityINFO int = iota + 1
	SeverityMEDIUM
	SeverityHIGH
	SeverityCRITICAL
	SeverityUnknown
)

func GetSeverityLevel(s string) int {
	switch s {
	case "info":
		return SeverityINFO
	case "medium":
		return SeverityMEDIUM
	case "high":
		return SeverityHIGH
	case "critical":
		return SeverityCRITICAL
	default:
		return SeverityUnknown
	}
}

var SeverityMap = map[int]string{
	SeverityINFO:     "info",
	SeverityMEDIUM:   "medium",
	SeverityHIGH:     "high",
	SeverityCRITICAL: "critical",
}

type Vuln struct {
	Name          string                 `json:"name"`
	Payload       map[string]interface{} `json:"payload,omitempty"`
	Detail        map[string]interface{} `json:"detail,omitempty"`
	SeverityLevel int                    `json:"severity"`
}

func (v *Vuln) GetPayload() string {
	return mapToString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return mapToString(v.Detail)
}

func (v *Vuln) String() string {
	s := v.Name
	if payload := v.GetPayload(); payload != "" {
		s += fmt.Sprintf(" payloads:%s", payload)
	}
	if detail := v.GetDetail(); detail != "" {
		s += fmt.Sprintf(" payloads:%s", detail)
	}
	return s
}

type Vulns []*Vuln

func (vs Vulns) String() string {
	var s string

	for _, vuln := range vs {
		s += fmt.Sprintf("[ %s: %s ] ", SeverityMap[vuln.SeverityLevel], vuln.String())
	}
	return s
}

func mapToString(m map[string]interface{}) string {
	if m == nil || len(m) == 0 {
		return ""
	}
	var s string
	for k, v := range m {
		s += fmt.Sprintf(" %s:%s ", k, v.(string))
	}
	return s
}

type Extracted struct {
	Name          string   `json:"name"`
	ExtractResult []string `json:"extract_result"`
}

func (e *Extracted) ToString() string {
	if len(e.ExtractResult) == 1 {
		if len(e.ExtractResult[0]) > 30 {
			return fmt.Sprintf("%s:%s ... %d bytes", e.Name, AsciiEncode(e.ExtractResult[0][:30]), len(e.ExtractResult[0]))
		}
		return fmt.Sprintf("%s:%s", e.Name, AsciiEncode(e.ExtractResult[0]))
	} else {
		return fmt.Sprintf("%s:%d items", e.Name, len(e.ExtractResult))
	}
}

type Extractor struct {
	Name            string           `json:"name"` // extractor name
	Regexps         []string         `json:"regex"`
	Tags            []string         `json:"tags"`
	CompiledRegexps []*regexp.Regexp `json:"-"`
}

func (e *Extractor) Compile() {
	e.CompiledRegexps = make([]*regexp.Regexp, len(e.Regexps))
	for i, r := range e.Regexps {
		e.CompiledRegexps[i] = regexp.MustCompile(r)
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
