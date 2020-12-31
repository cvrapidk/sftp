package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"math/rand"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func main() {
	var server string
	var username string
	var password string
	var privateKey string
	var remoteFile string
	var inputFile string
	var outputFile string
	var port int

	flag.StringVar(&server, "server", "", "Set server")
	flag.StringVar(&username, "username", "", "Set username")
	flag.StringVar(&password, "password", "", "Set password")
	flag.StringVar(&privateKey, "private-key", "", "Set path to SSH private key")
	flag.StringVar(&remoteFile, "remote-file", "", "Set remote file")
	flag.StringVar(&outputFile, "output-file", "", "Set output file")
	flag.StringVar(&inputFile, "input-file", "", "Set input file")
	flag.IntVar(&port, "port", 22, "Set SSH port")
	flag.Parse()

	if server == "" {
		fmt.Printf("Missing flag: server\n")
		os.Exit(1)
	}

	if username == "" {
		fmt.Printf("Missing flag: username\n")
		os.Exit(1)
	}

	if password == "" && privateKey == "" {
		fmt.Printf("Missing flag: password\n")
		os.Exit(1)
	}

	if remoteFile == "" {
		fmt.Printf("Missing flag: remote-file\n")
		os.Exit(1)
	}

	if outputFile == "" && inputFile == "" {
		fmt.Printf("Missing flag: output-file and input-file\n")
		os.Exit(1)
	}

	// Get host public key
	hostKey := getHostKey(server)

	// Set hostkey callback
	hostKeyCallback := ssh.FixedHostKey(hostKey)

	// Check if host key is nil
	if hostKey == nil {
		// Set hostkey callback
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	// Set auth
	auths := []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, _ := range answers {
			answers[i] = password
		}
		return answers, nil
	})}

	if privateKey != "" {
		// Get file
		key, err := ioutil.ReadFile(privateKey)
		if err != nil {
			log.Fatalf("Unable to read private key: %v", err)
			os.Exit(1)
		}

		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("Unable to parse private key: %v", err)
			os.Exit(1)
		}

		// Set auth
		auths = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}

	// Create client
	config := &ssh.ClientConfig{
		User: username,
		Auth: auths,
		//HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: hostKeyCallback,
	}

	// Combine server and port
	endpoint := fmt.Sprintf("%s:%d", server, port)

	// Connect
	connection, err := ssh.Dial("tcp", endpoint, config)
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()

	// Create new SFTP client
	client, err := sftp.NewClient(connection)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Copy source file to destination file
	if outputFile != "" {
		// Create destination file
		dstFile, err := os.Create(outputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer dstFile.Close()

		// Open source file
		srcFile, err := client.Open(remoteFile)
		if err != nil {
			log.Fatal(err)
		}

		bytes, err := io.Copy(dstFile, srcFile)
		if err != nil {
			log.Fatal(err)
		}

		// Flush in-memory copy
		err = dstFile.Sync()
		if err != nil {
			log.Fatal(err)
		}

		// Tell the world
		fmt.Printf("%d bytes downloaded\n", bytes)
	} else if inputFile != "" {
		// Create a temporary filename
		uploadRemoteFile := fmt.Sprintf("%s.temp.%s", remoteFile, RandStringBytes(8))

		// Create destination file
		dstFile, err := client.Create(uploadRemoteFile)
		if err != nil {
			log.Fatal(err)
		}
		defer dstFile.Close()

		// Open source file
		srcFile, err := os.Open(inputFile)
		if err != nil {
			log.Fatal(err)
		}

		bytes, err := io.Copy(dstFile, srcFile)
		if err != nil {
			log.Fatal(err)
		}

		// Rename temporary to input filename
		err = client.PosixRename(uploadRemoteFile, remoteFile)
		if err != nil {
			log.Fatal(err)
		}

		// Tell the world
		fmt.Printf("%d bytes uploaded\n", bytes)
	}
}

func getHostKey(host string) ssh.PublicKey {
	if runtime.GOOS == "windows" {
		return nil
	}

	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				log.Fatalf("error parsing %q: %v", fields[2], err)
			}
			break
		}
	}

	if hostKey == nil {
		log.Fatalf("no hostkey found for %s", host)
	}

	return hostKey
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}