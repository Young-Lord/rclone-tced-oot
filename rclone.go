package main

import (
	_ "github.com/Young-Lord/rclone-tced-oot/backend/tced" // import out-of-tree tced backend
	_ "github.com/rclone/rclone/backend/all"               // import upstream backends
	"github.com/rclone/rclone/cmd"
	_ "github.com/rclone/rclone/cmd/all"    // import all commands
	_ "github.com/rclone/rclone/lib/plugin" // import plugins
)

func main() {
	cmd.Main()
}
