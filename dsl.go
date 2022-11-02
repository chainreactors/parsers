package parsers

import "strings"

func DSLParserToString(s string) string {
	return string(DSLParser(s))
}

func DSLParser(s string) []byte {
	var bs []byte
	var operator, content string

	if i := strings.Index(s, "|"); i > 0 {
		operator = s[:i]
		content = s[i+1:]
	} else {
		return []byte(s)
	}

	switch operator {
	case "b64de":
		bs = Base64Decode(content)
	case "b64en":
		bs = []byte(Base64Encode([]byte(content)))
	case "unhex":
		bs = UnHexlify(content)
	case "hex":
		bs = []byte(Hexlify([]byte(content)))
	case "md5":
		bs = []byte(Md5Hash([]byte(content)))
	default:
		bs = []byte(content)
	}
	return bs
}
