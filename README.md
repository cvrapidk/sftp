# sftp

This tool can download and upload files to a remote SFTP server.

## Installation

$ make

## Usage

| Parameter | Description |
| --------- | ----------- |
| server | FQDN to the remote server |
| username | Username |
| password | Password |
| i | Set path to SSH private key |
| F | Set path to SSH config |
| remote-file | Full path to remote file |
| output-file | Full path to output file (download) |
| input-file | Full path to input file (upload) |
| overwrite-file | Overwrite file |
| port | Remote server port |

### Use user@server

You can also use $ sftp --remote-file remotefile.csv --output-file remotefile.csv user@server

Please be aware that user@server needs to be at the end of the argument list due to drawbacks in the Go flag package.

### Download

$ sftp --server example.com --username test --password test --remote-file remotefile.csv --output-file remotefile.csv

### Upload

$ sftp --server example.com --username test --password test --remote-file remotefile.csv --input-file remotefile.csv
