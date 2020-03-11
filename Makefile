.PHONY: all

all: clean test linux mac windows

clean:
	rm -f sftpgrab-linux-amd64 sftpgrab-mac-amd64 sftpgrab-windows-amd64.exe
	gofmt -w main.go

test:
	go test main.go

linux:
	env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o sftpgrab-linux-amd64 main.go

mac:
	env GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o sftpgrab-mac-amd64 main.go

windows:
	env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o sftpgrab-windows-amd64.exe main.go