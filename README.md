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
| remote-file | Full path to remote file |
| output-file | Full path to output file (download) |
| input-file | Full path to input file (upload) |
| overwrite-file | Overwrite file |
| port | Remote server port |

### Download

$ sftp --server example.com --username test --password test --remote-file remotefile.csv --output-file remotefile.csv

### Upload

$ sftp --server example.com --username test --password test --remote-file remotefile.csv --input-file remotefile.csv
