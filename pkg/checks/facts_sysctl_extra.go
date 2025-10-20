package checks

func SysctlValueDefault(key string) (string, error) {
	// key is like "net.ipv6.conf.default.accept_ra"
	return SysctlValue(key)
}
