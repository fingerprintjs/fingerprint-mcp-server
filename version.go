package fpmcpserver

import "runtime/debug"

func Version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	// When imported as a dependency, find ourselves in Deps
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/fingerprintjs/fingerprint-mcp-server" {
			return dep.Version
		}
	}

	// When running as the main module (dev), Main.Version is "(devel)"
	return bi.Main.Version
}
