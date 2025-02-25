package parsers

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/logs"
	"strconv"
	"strings"
)

type ZombieTaskMod int

const (
	ZombieModBrute ZombieTaskMod = 0 + iota
	ZombieModUnauth
	ZombieModCheck
	ZombieModSniper
	ZombieModPitchfork
)

func (m ZombieTaskMod) String() string {
	switch m {
	case ZombieModBrute:
		return "brute"
	case ZombieModUnauth:
		return "unauth"
	case ZombieModCheck:
		return "check"
	case ZombieModSniper:
		return "sniper"
	case ZombieModPitchfork:
		return "pitchfork"
	default:
		return "unknown"
	}
}

// static plugin, load template will be added
// ZombieMap map zombie service to gogo finger
var ZombieMap = map[string]string{
	"mariadb":    "mysql",
	"mysql":      "mysql",
	"rdp":        "rdp",
	"oracle":     "oracle",
	"sqlserver":  "mssql",
	"mssql":      "mssql",
	"smb":        "smb",
	"redis":      "redis",
	"vnc":        "vnc",
	"postgresql": "postgresql",
	"mongo":      "mongo",
	"ssh":        "ssh",
	"ftp":        "ftp",
	"socks5":     "socks5",
	"rsync":      "rsync",
	"telnet":     "telnet",
}

// RegisterZombieServiceAlias register alias for zombie service after load templates
func RegisterZombieServiceAlias() {
	ZombieMap["tomcat"] = "tomcat"
	ZombieMap["tomcat-manager"] = "tomcat"
}

type ZombieInput struct {
	IP      string            `json:"ip"`
	Port    string            `json:"port"`
	Service string            `json:"service"`
	Scheme  string            `json:"scheme"`
	Param   map[string]string `json:"param,omitempty"`
}

type ZombieResult struct {
	IP       string            `json:"ip"`
	Port     string            `json:"port"`
	Service  string            `json:"service"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	Scheme   string            `json:"scheme"`
	Mod      ZombieTaskMod     `json:"mod"`
	Param    map[string]string `json:"param,omitempty"`
}

func (r *ZombieResult) String() string {
	return fmt.Sprintf("%s://%s:%s", r.Service, r.IP, r.Port)
}

func (r *ZombieResult) Address() string {
	return r.IP + ":" + r.Port
}

func (r *ZombieResult) URI() string {
	if r.Scheme != "" {
		return r.Scheme + "://" + r.Address()
	} else {
		return r.Service + "://" + r.Address()
	}
}

func (r *ZombieResult) Full() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("[%s] ", r.Mod.String()))
	s.WriteString(r.URI())
	if r.Username != "" {
		s.WriteString(" " + r.Username)
	}
	if r.Password != "" {
		s.WriteString(" " + r.Password)
	}
	if len(r.Param) != 0 {
		s.WriteString(" " + fmt.Sprintf("%v", r.Param))
	}
	if r.Mod == ZombieModCheck {
		s.WriteString(", " + r.Service + " maybe honeypot or unauth!!!\n")
	} else {
		s.WriteString(", " + r.Service + " login successfully\n")
	}

	return s.String()
}

func (r *ZombieResult) Json() string {
	bs, err := json.Marshal(r)
	if err != nil {
		logs.Log.Error(err.Error())
		return ""
	}
	return string(bs) + "\n"
}

func (r *ZombieResult) Format(form string) string {
	switch form {
	case "json", "jl":
		return r.Json()
	case "csv":
		return ""
	default:
		return r.String()
	}
}

func (r *ZombieResult) URL() string {
	return fmt.Sprintf("%s://%s:%s@%s:%s", r.Scheme, r.Username, r.Password, r.IP, r.Port)
}

func (r *ZombieResult) UintPort() uint16 {
	p, _ := strconv.Atoi(r.Port)
	return uint16(p)
}
