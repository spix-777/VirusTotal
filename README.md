# VirusTotal API v3 Client

This is a command-line tool written in Go that interacts with the VirusTotal API v3. It calculates the SHA256 checksum of a file and retrieves scan results from VirusTotal.

## Prerequisites

- Go programming language (version 1.14+)
- VirusTotal API key

## Installation

1. Clone the repository:

```shell
git clone https://github.com/your-repo.git
```

2. Change into the project directory:

```shell
cd your-repo
```

3. Build the executable:

```shell
go build
```

## Usage

```shell
./your-repo -f <filename> -apikey <api_key> [-v]
```

- `-f <filename>`: Specifies the path to the file for which to calculate the SHA256 checksum and scan.
- `-apikey <api_key>`: Specifies your VirusTotal API key.
- `-v`: Prints the version information.

## Examples

Calculate the SHA256 checksum and scan a file:

```shell
./your-repo -f /path/to/file -apikey YOUR_API_KEY
```

Print the version information:

```shell
./your-repo -v
```

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

- [VirusTotal](https://www.virustotal.com) - VirusTotal API provider