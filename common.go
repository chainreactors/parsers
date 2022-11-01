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
var FrameFromMap = map[int]string{
	FrameFromACTIVE:   "active",
	FrameFromICO:      "ico",
	FrameFromNOTFOUND: "404",
	FrameFromGUESS:    "guess",
}

type Framework struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	From    int    `json:"-"`
	FromStr string `json:"from"`
	IsFocus bool   `json:"is_focus"`
	Data    string `json:"-"`
}

func (f Framework) ToString() string {
	var s = f.Name
	if f.IsFocus {
		s = "focus:" + s
	}

	if f.Version != "" {
		s += ":" + strings.Replace(f.Version, ":", "_", -1)
	}
	if f.From != FrameFromNone {
		s += ":" + f.FromStr
	}
	return s
}

type Frameworks []*Framework

func (fs Frameworks) ToString() string {
	frameworkStrs := make([]string, len(fs))
	for i, f := range fs {
		if f.From == FrameFromGUESS && NoGuess {
			continue
		}
		frameworkStrs[i] = f.ToString()
	}
	return strings.Join(frameworkStrs, "||")
}

func (fs Frameworks) GetNames() []string {
	var titles []string
	for _, f := range fs {
		if f.From != FrameFromGUESS {
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
)

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
	Severity      string                 `json:"severity"`
	SeverityLevel int                    `json:"-"`
}

func (v *Vuln) GetPayload() string {
	return mapToString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return mapToString(v.Detail)
}

func (v *Vuln) ToString() string {
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

func (vs Vulns) ToString() string {
	var s string

	for _, vuln := range vs {
		s += fmt.Sprintf("[ %s: %s ] ", vuln.Severity, vuln.ToString())
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
