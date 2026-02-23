# rclone-tced-oot

Out-of-tree custom rclone binary with the `tced` backend built in.

## Layout

- `rclone.go`: custom entrypoint that imports upstream rclone plus `tced`.
- `backend/tced`: out-of-tree `tced` backend implementation.

## Build

```bash
go mod tidy
go build -o rclone-tced .
```

## Use

```bash
./rclone-tced version
./rclone-tced config
```

Pick storage type `tced` in `rclone config`.

## Build and use plugin (.so)

```bash
go mod tidy
go build -buildmode=plugin -o librcloneplugin_backend_tced.so ./plugin/backend_tced
```

Use it in local rclone:

```bash
mkdir -p ~/.config/rclone/plugins
cp librcloneplugin_backend_tced.so ~/.config/rclone/plugins/
export RCLONE_PLUGIN_PATH="$HOME/.config/rclone/plugins"

rclone help backends | grep tced
```

Notes:

- Go plugin mode is supported on Linux/macOS.
- Plugin and host rclone must be built from compatible rclone/go versions.
- Recommended: build host binary and plugin from the same source tree and Go toolchain.
- CI release artifacts include the custom binary only; plugin `.so` is built locally.

## Notes

- This project tracks upstream rclone via `go.mod`.
- Update upstream dependency with:

```bash
go get github.com/rclone/rclone@latest
go mod tidy
```

## Credit

- [1357310795/TboxWebdav](https://github.com/1357310795/TboxWebdav)
