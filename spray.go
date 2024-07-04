package parsers

import (
	"encoding/json"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/logs"
	"strconv"
	"strings"
)

type SpraySource int

const (
	CheckSource SpraySource = iota + 1
	InitRandomSource
	InitIndexSource
	RedirectSource
	CrawlSource
	FingerSource
	WordSource
	WafSource
	RuleSource
	BakSource
	CommonFileSource
	UpgradeSource
	RetrySource
	AppendSource
)

// Name return the name of the source
func (s SpraySource) Name() string {
	switch s {
	case CheckSource:
		return "check"
	case InitRandomSource:
		return "random"
	case InitIndexSource:
		return "index"
	case RedirectSource:
		return "redirect"
	case CrawlSource:
		return "crawl"
	case FingerSource:
		return "finger"
	case WordSource:
		return "word"
	case WafSource:
		return "waf"
	case RuleSource:
		return "rule"
	case BakSource:
		return "bak"
	case CommonFileSource:
		return "common"
	case UpgradeSource:
		return "upgrade"
	case RetrySource:
		return "retry"
	case AppendSource:
		return "append"
	default:
		return "unknown"
	}
}

type SprayResult struct {
	Number       int               `json:"number"`
	IsValid      bool              `json:"valid"`
	IsFuzzy      bool              `json:"fuzzy"`
	UrlString    string            `json:"url"`
	Path         string            `json:"path"`
	Host         string            `json:"host"`
	BodyLength   int               `json:"body_length"`
	ExceedLength bool              `json:"-"`
	HeaderLength int               `json:"header_length"`
	RedirectURL  string            `json:"redirect_url,omitempty"`
	FrontURL     string            `json:"front_url,omitempty"`
	Status       int               `json:"status"`
	Spended      int64             `json:"spend"` // 耗时, 毫秒
	ContentType  string            `json:"content_type"`
	Title        string            `json:"title"`
	Frameworks   common.Frameworks `json:"frameworks"`
	Extracteds   Extracteds        `json:"extracts"`
	ErrString    string            `json:"error"`
	Reason       string            `json:"reason"`
	Source       SpraySource       `json:"source"`
	ReqDepth     int               `json:"depth"`
	Distance     uint8             `json:"distance"`
	Unique       uint16            `json:"unique"`
	*Hashes      `json:"hashes"`
}

func (bl *SprayResult) Get(key string) string {
	switch key {
	case "url":
		return bl.UrlString
	case "host":
		return bl.Host
	case "content_type", "type":
		return bl.ContentType
	case "title":
		return bl.Title
	case "redirect":
		return bl.RedirectURL
	case "md5":
		if bl.Hashes != nil {
			return bl.Hashes.BodyMd5
		} else {
			return ""
		}
	case "simhash":
		if bl.Hashes != nil {
			return bl.Hashes.BodySimhash
		} else {
			return ""
		}
	case "mmh3":
		if bl.Hashes != nil {
			return bl.Hashes.BodySimhash
		} else {
			return ""
		}
	case "stat", "status":
		return strconv.Itoa(bl.Status)
	case "spend":
		return strconv.Itoa(int(bl.Spended)) + "ms"
	case "length":
		return strconv.Itoa(bl.BodyLength)
	case "sim", "distance":
		return "sim:" + strconv.Itoa(int(bl.Distance))
	case "source":
		return bl.Source.Name()
	case "unique":
		return strconv.Itoa(int(bl.Unique))
	case "extract":
		return bl.Extracteds.String()
	case "frame", "framework":
		var s strings.Builder
		for _, f := range bl.Frameworks {
			s.WriteString(" [" + f.String() + "]")
		}
		return s.String()
	case "cpe", "fsb":
		return strings.Join(bl.Frameworks.CPE(), ",")
	case "uri":
		return strings.Join(bl.Frameworks.URI(), ",")
	case "wfn":
		return strings.Join(bl.Frameworks.WFN(), ",")
	case "full":
		return bl.String()
	default:
		return ""
	}
}

func (bl *SprayResult) FramesColorString() string {
	var s strings.Builder
	for _, f := range bl.Frameworks {
		if f.IsFocus {
			s.WriteString(logs.RedBold(" [" + strings.Replace(f.String(), "focus:", "", -1) + "]"))
		} else {
			s.WriteString(logs.Cyan(" [" + f.String() + "]"))
		}
	}
	return s.String()
}

func (bl *SprayResult) Additional(key string) string {
	if key == "frame" || key == "extract" {
		return bl.Get(key)
	} else if v := bl.Get(key); v != "" {
		return " [" + v + "]"
	} else {
		return ""
	}
}

func (bl *SprayResult) Format(probes []string) string {
	var line strings.Builder
	if bl.FrontURL != "" {
		line.WriteString("\t")
		line.WriteString(bl.FrontURL)
		line.WriteString(" -> ")
	}
	line.WriteString(bl.UrlString)
	if bl.Host != "" {
		line.WriteString(" (" + bl.Host + ")")
	}

	if bl.Reason != "" {
		line.WriteString(" ,")
		line.WriteString(bl.Reason)
	}
	if bl.ErrString != "" {
		line.WriteString(" ,err: ")
		line.WriteString(bl.ErrString)
		return line.String()
	}

	for _, p := range probes {
		line.WriteString(" ")
		line.WriteString(bl.Additional(p))
	}

	return line.String()
}

func (bl *SprayResult) ColorString() string {
	var line strings.Builder
	line.WriteString(logs.GreenLine(padding("["+bl.Source.Name()+"]", 10) + "\t"))
	line.WriteString(logs.GreenBold(strconv.Itoa(bl.Status)))
	line.WriteString("\t")
	line.WriteString(logs.Yellow(strconv.Itoa(bl.BodyLength)))
	if bl.ExceedLength {
		line.WriteString(logs.Yellow("(exceed)"))
	}
	line.WriteString("\t")
	line.WriteString(logs.Yellow(strconv.Itoa(int(bl.Spended)) + "ms"))
	line.WriteString("\t")
	if bl.FrontURL != "" {
		line.WriteString(logs.Green(bl.FrontURL))
		line.WriteString(" --> ")
	}
	line.WriteString(logs.GreenBold(bl.UrlString))
	if bl.Host != "" {
		line.WriteString(logs.Green(" (" + bl.Host + ")"))
	}
	if bl.RedirectURL != "" {
		line.WriteString(" " + logs.Green(bl.RedirectURL))
		line.WriteString(" --> ")
	}

	line.WriteString(logs.GreenLine(bl.Additional("title")))

	if bl.Distance != 0 {
		line.WriteString(logs.GreenLine(bl.Additional("sim")))
	}

	if bl.Reason != "" {
		line.WriteString(logs.Yellow(" [reason: " + bl.Reason + "]"))
	}
	if bl.ErrString != "" {
		line.WriteString(logs.RedBold(" [err: " + bl.ErrString + "]"))
		return line.String()
	}

	line.WriteString(bl.FramesColorString())
	line.WriteString(logs.Cyan(bl.Additional("extract")))
	if len(bl.Extracteds) > 0 {
		for _, e := range bl.Extracteds {
			line.WriteString("\n  " + e.Name + " (" + strconv.Itoa(len(e.ExtractResult)) + ") items : \n\t")
			line.WriteString(logs.GreenLine(strings.Join(e.ExtractResult, "\n\t")))
		}
	}
	return line.String()
}

func (bl *SprayResult) String() string {
	var line strings.Builder
	line.WriteString(padding("["+bl.Source.Name()+"]", 10) + "\t")

	line.WriteString(strconv.Itoa(bl.Status))
	line.WriteString("\t")
	line.WriteString(strconv.Itoa(bl.BodyLength))
	if bl.ExceedLength {
		line.WriteString("(exceed)")
	}
	line.WriteString("\t")
	line.WriteString(strconv.Itoa(int(bl.Spended)) + "ms")
	line.WriteString("\t")
	if bl.FrontURL != "" {
		line.WriteString(" " + bl.FrontURL)
		line.WriteString(" --> ")
	}
	line.WriteString(bl.UrlString)
	if bl.Host != "" {
		line.WriteString(" (" + bl.Host + ")")
	}
	if bl.RedirectURL != "" {
		line.WriteString(" --> ")
		line.WriteString(bl.RedirectURL)
		line.WriteString(" ")
	}

	line.WriteString(bl.Additional("title"))

	if bl.Distance != 0 {
		line.WriteString(logs.GreenLine(bl.Additional("sim")))
	}

	if bl.Reason != "" {
		line.WriteString(" [reason: " + bl.Reason + "]")
	}
	if bl.ErrString != "" {
		line.WriteString(" [err: " + bl.ErrString + "]")
		return line.String()
	}

	line.WriteString(bl.Additional("frame"))
	line.WriteString(bl.Additional("extract"))
	if len(bl.Extracteds) > 0 {
		for _, e := range bl.Extracteds {
			line.WriteString("\n  " + e.Name + " (" + strconv.Itoa(len(e.ExtractResult)) + ") items : \n\t")
			line.WriteString(strings.Join(e.ExtractResult, "\n\t"))
		}
	}
	return line.String()
}

func (bl *SprayResult) Jsonify() string {
	bs, err := json.Marshal(bl)
	if err != nil {
		return ""
	}
	return string(bs)
}

func padding(s string, size int) string {
	if len(s) >= size {
		return s
	}
	return s + strings.Repeat(" ", size-len(s))
}
