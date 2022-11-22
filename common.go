package parsers

import (
	"fmt"
	"strings"
)

const (
	FrameFromNone = iota
	FrameFromACTIVE
	FrameFromICO
	FrameFromNOTFOUND
	FrameFromGUESS
)

var NoGuess bool
var frameFromMap = map[int]string{
	FrameFromNone:     "",
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
		return FrameFromNone
	}
}

type Framework struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	From    int      `json:"-"`
	Froms   []int    `json:"froms,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	IsFocus bool     `json:"is_focus,omitempty"`
	Data    string   `json:"-"`
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

	if len(f.Froms) > 0 {
		s.WriteString(":")
		for _, from := range f.Froms {
			if from != FrameFromNone {
				s.WriteString(frameFromMap[from] + ",")
			}
		}
		return s.String()[:s.Len()-2]
	}
	return s.String()
}

func (f *Framework) IsGuess() bool {
	var is bool
	for _, from := range f.Froms {
		if from == FrameFromGUESS {
			is = true
		} else {
			return false
		}
	}
	return is
}

type Frameworks map[string]*Framework

func (fs Frameworks) Add(other *Framework) {
	if frame, ok := fs[other.Name]; ok {
		frame.Froms = append(frame.Froms, other.From)
	} else {
		other.Froms = []int{other.From}
		fs[other.Name] = other
	}
}

func (fs Frameworks) String() string {
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
	var titles []string
	for _, f := range fs {
		if !f.IsGuess() {
			titles = append(titles, f.Name)
		}
	}
	return titles
}

func (fs Frameworks) IsFocus() bool {
	for _, f := range fs {
		if f.IsFocus {
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
