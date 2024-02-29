package parsers

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

type ZombieInput struct {
	IP      string            `json:"ip"`
	Port    string            `json:"port"`
	Service string            `json:"service"`
	Scheme  string            `json:"scheme"`
	Param   map[string]string `json:"param,omitempty"`
}
