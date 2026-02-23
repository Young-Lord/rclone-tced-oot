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

## Notes

- This project tracks upstream rclone via `go.mod`.
- Update upstream dependency with:

```bash
go get github.com/rclone/rclone@latest
go mod tidy
```

- If upstream rclone later includes `tced`, remove the import of
  `github.com/Young-Lord/rclone-tced-oot/backend/tced` in `rclone.go` to avoid duplicate backend
  registration.
