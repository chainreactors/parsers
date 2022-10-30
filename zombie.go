package parsers

var zombieMap = map[string]string{
	"mariadb":   "MYSQL",
	"mysql":     "MYSQL",
	"rdp":       "RDP",
	"oracle":    "ORACLE",
	"sqlserver": "MSSQL",
	"mssql":     "MSSQL",
	"smb":       "SMB",
	"redis":     "REDIS",
	"vnc":       "VNC",
	//"elasticsearch": "ELASTICSEARCH",
	"postgresql": "POSTGRESQL",
	"mongo":      "MONGO",
	"ssh":        "SSH",
	"ftp":        "FTP",
}

type ZombieInput struct {
	IP      string `json:"ip"`
	Port    string `json:"port"`
	Service string `json:"service"`
}
