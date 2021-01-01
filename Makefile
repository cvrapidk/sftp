.PHONY: all

all: clean test linux mac windows

clean:
	rm -f sftp-linux-amd64 sftp-mac-amd64 sftp-windows-amd64.exe
	gofmt -w main.go

test:
	go test main.go

linux:
	env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sftp-linux-amd64 main.go

mac:
	env GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sftp-mac-amd64 main.go

windows:
	env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sftp-windows-amd64.exe main.go