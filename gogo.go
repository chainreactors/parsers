package parsers

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/logs"
	"strings"
)

func NewGOGOResult(ip, port string) *GOGOResult {
	return &GOGOResult{
		Ip:         ip,
		Port:       port,
		Protocol:   "tcp",
		Status:     "tcp",
		Frameworks: make(Frameworks),
	}
}

type GOGOResult struct {
	Ip         string              `json:"ip"`                   // ip
	Port       string              `json:"port"`                 // port
	Uri        string              `json:"uri,omitempty"`        // uri
	Os         string              `json:"os,omitempty"`         // os
	Host       string              `json:"host,omitempty"`       // host
	Frameworks Frameworks          `json:"frameworks,omitempty"` // framework
	Vulns      Vulns               `json:"vulns,omitempty"`
	Extracteds map[string][]string `json:"extracted,omitempty"`
	Protocol   string              `json:"protocol"` // protocol
	Status     string              `json:"status"`   // http_stat
	Language   string              `json:"language"`
	Title      string              `json:"title"`   // title
	Midware    string              `json:"midware"` // midware
}

func (result *GOGOResult) IsHttp() bool {
	if strings.HasPrefix(result.Protocol, "http") {
		return true
	}
	return false
}

func (result *GOGOResult) GetBaseURL() string {
	return fmt.Sprintf("%s://%s:%s", result.Protocol, result.Ip, result.Port)
}

func (result *GOGOResult) GetTarget() string {
	return fmt.Sprintf("%s:%s", result.Ip, result.Port)
}

func (result *GOGOResult) GetURL() string {
	if result.IsHttp() {
		return result.GetBaseURL() + result.Uri
	} else {
		return result.GetBaseURL()
	}
}

func (result *GOGOResult) GetExtractStat() string {
	if len(result.Extracteds) > 0 {
		var s []string
		for name, ss := range result.Extracteds {
			if tmps := strings.Join(ss, ","); len(tmps) < 50 {
				s = append(s, fmt.Sprintf("%s:%s", name, tmps))
			} else {
				s = append(s, fmt.Sprintf("%s:%d items", name, len(ss)))
			}
		}
		return fmt.Sprintf("[ extracts: %s ]", strings.Join(s, ", "))
	} else {
		return ""
	}
}

func (result *GOGOResult) NoFramework() bool {
	if len(result.Frameworks) == 0 {
		return true
	}
	return false
}

func (result *GOGOResult) GetFirstFramework() *Framework {
	if !result.NoFramework() {
		for _, frame := range result.Frameworks {
			return frame
		}
	}
	return nil
}

func (result *GOGOResult) Get(key string) string {
	switch key {
	case "ip":
		return result.Ip
	case "port":
		return result.Port
	case "status", "stat":
		return result.Status
	case "frameworks", "framework", "frame":
		return result.Frameworks.String()
	case "vulns", "vuln":
		return result.Vulns.String()
	case "host":
		return result.Host
	case "title":
		return result.Title
	case "target":
		return result.GetTarget()
	case "url":
		return result.GetBaseURL()
	case "midware":
		return result.Midware
	//case "hash":
	//	return result.Hash
	case "language":
		return result.Language
	case "protocol":
		return result.Protocol
	case "os":
		return result.Os
	//case "extract":
	//	return result.Extracts.ToString()
	default:
		return ""
	}
}

func (result *GOGOResult) ColorOutput() string {
	s := fmt.Sprintf("[+] %s\t%s\t%s\t%s\t%s [%s] %s %s\n", result.GetURL(), result.Midware, result.Language, logs.Blue(result.Frameworks.String()), result.Host, logs.Yellow(result.Status), logs.Blue(result.Title), logs.Red(result.Vulns.String()))
	return s
}

func (result *GOGOResult) FullOutput() string {
	s := fmt.Sprintf("[+] %s\t%s\t%s\t%s\t%s [%s] %s %s %s\n", result.GetURL(), result.Midware, result.Language, result.Frameworks.String(), result.Host, result.Status, result.Title, result.Vulns.String(), result.GetExtractStat())
	return s
}

func (result *GOGOResult) JsonOutput() string {
	jsons, _ := json.Marshal(result)
	return string(jsons)
}

func (result *GOGOResult) CsvOutput() string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", result.Ip, result.Port, result.GetURL(), result.Status, slashComma(result.Title), result.Host, result.Language, slashComma(result.Midware), slashComma(result.Frameworks.String()), slashComma(result.Vulns.String()))
}

func (result *GOGOResult) ValuesOutput(outType string) string {
	outs := strings.Split(outType, ",")
	for i, out := range outs {
		outs[i] = result.Get(out)
	}
	return strings.Join(outs, "\t") + "\n"
}

func slashComma(s string) string {
	return strings.Replace(s, ",", "\\,", -1)
}

func (result *GOGOResult) Filter(k, v, op string) bool {
	var matchfunc func(string, string) bool
	if op == "::" {
		matchfunc = strings.Contains
	} else if op == "==" {
		matchfunc = strings.EqualFold
	} else if op == "!:" {
		matchfunc = func(s1 string, s2 string) bool {
			return !strings.Contains(s1, s2)
		}
	} else if op == "!=" {
		matchfunc = func(s1 string, s2 string) bool {
			return !strings.EqualFold(s1, s2)
		}
	} else {
		logs.Log.Warn("illegal operator, please input one of [::, ==, !:, !=]")
	}

	if matchfunc(strings.ToLower(result.Get(k)), v) {
		return true
	}
	return false
}

type GOGOConfig struct {
	IP            string   `json:"ip"`
	IPlist        []string `json:"ips"`
	Ports         string   `json:"ports"`
	JsonFile      string   `json:"json_file"`
	ListFile      string   `json:"list_file"`
	Threads       int      `json:"threads"` // 线程数
	Mod           string   `json:"mod"`     // 扫描模式
	AliveSprayMod []string `json:"alive_spray"`
	PortSpray     bool     `json:"port_spray"`
	Exploit       string   `json:"exploit"`
	JsonType      string   `json:"json_type"`
	VersionLevel  int      `json:"version_level"`
}

func (config *GOGOConfig) GetTargetName() string {
	var target string
	if config.ListFile != "" {
		target = config.ListFile
	} else if config.JsonFile != "" {
		target = config.JsonFile
	} else if config.Mod == "a" {
		target = "auto"
	} else if config.IP != "" {
		target = config.IP
	}
	return target
}

type GOGOResults []*GOGOResult

func (rs GOGOResults) FilterWithString(name string) GOGOResults {
	// 过滤指定数据
	var results GOGOResults
	if name == "focus" {
		results = rs.Filter("frame", "focus", "::")
	} else if name == "vuln" {
		results = rs.Filter("vuln", "high", "::")
		results = append(results, rs.Filter("vuln", "critical", "::")...)
	} else if name == "domain" {
		//todo
	} else {
		// 过滤指定数据
		if strings.Contains(name, "::") {
			kv := strings.Split(name, "::")
			results = rs.Filter(kv[0], kv[1], "::")
		} else if strings.Contains(name, "==") {
			kv := strings.Split(name, "==")
			results = rs.Filter(kv[0], kv[1], "==")
		} else if strings.Contains(name, "!=") {
			kv := strings.Split(name, "!=")
			results = rs.Filter(kv[0], kv[1], "!=")
		} else if strings.Contains(name, "!:") {
			kv := strings.Split(name, "!:")
			results = rs.Filter(kv[0], kv[1], "!:")
		}
	}

	return results
}

func (rs GOGOResults) Filter(k, v, op string) GOGOResults {
	var filtedres GOGOResults
	v = strings.ToLower(v)
	for _, result := range rs {
		if result.Filter(k, v, op) {
			filtedres = append(filtedres, result)
		}
	}
	return filtedres
}

func (rs GOGOResults) GetValues(key string) []string {
	values := make([]string, len(rs))
	for i, result := range rs {
		//if focus && !result.Frameworks.IsFocus() {
		//	// 如果需要focus, 则跳过非focus标记的framework
		//	continue
		//}
		values[i] = result.Get(key)
	}
	return values
}

type GOGOData struct {
	Config GOGOConfig  `json:"config"`
	IP     string      `json:"ip"`
	Data   GOGOResults `json:"data"`
}

func (rd *GOGOData) Filter(name string) GOGOResults {
	return rd.Data.FilterWithString(name)
}

func (rd *GOGOData) ToConfig() string {
	// 输出配置信息
	var configstr string
	configstr = fmt.Sprintf("Scan Target: %s, Ports: %s, Mod: %s \n", rd.Config.GetTargetName(), rd.Config.Ports, rd.Config.Mod)
	configstr += fmt.Sprintf("Exploit: %s, Version level: %d \n", rd.Config.Exploit, rd.Config.VersionLevel)
	if rd.IP != "" {
		configstr += fmt.Sprintf("Internet IP: %s", rd.IP)
	}
	return configstr
}

func (rd *GOGOData) ToValues(outType string) string {
	outs := strings.Split(outType, ",")
	outvalues := make([][]string, len(outs))
	ss := make([]string, len(rd.Data))
	for i, out := range outs {
		outvalues[i] = rd.Data.GetValues(out)
	}

	for i := 0; i < len(ss); i++ {
		for j := 0; j < len(outvalues); j++ {
			ss[i] += outvalues[j][i] + "\t"
		}
		strings.TrimSpace(ss[i])
	}

	return strings.Join(ss, "\n")
}

func (rd *GOGOData) ToZombie() string {
	var zms []ZombieInput
	for _, r := range rd.Data {
		f := r.GetFirstFramework()
		if f == nil {
			continue
		}
		if service, ok := ZombieMap[strings.ToLower(f.Name)]; ok {
			zms = append(zms, ZombieInput{
				IP:      r.Ip,
				Port:    r.Port,
				Service: strings.ToLower(service),
			})
		}
	}

	s, err := json.Marshal(zms)
	if err != nil {
		logs.Log.Error(err.Error())
		return ""
	}
	return string(s)
}

func (rd *GOGOData) ToJson() string {
	content, _ := json.Marshal(rd)
	return string(content)
}

func (rd *GOGOData) ToCsv() string {
	var s strings.Builder
	s.WriteString("ip,port,url,status,title,host,language,midware,frame,vuln,extract\n")
	for _, r := range rd.Data {
		s.WriteString(r.CsvOutput())
	}
	return s.String()
}
