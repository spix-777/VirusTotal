# VirusTotal API v3 Client

This is a command-line tool written in Go that interacts with the VirusTotal API v3. It calculates the SHA256 checksum of a file and retrieves scan results from VirusTotal.

## Prerequisites

- Go programming language (version 1.14+)
- VirusTotal API key

## Installation

1. Clone the repository:

```shell
git clone https://github.com/spix-777/VirusTotal
```

2. Change into the project directory:

```shell
cd VirusTotal
```

3. Build the executable:

```shell
go build
```

## Usage

```shell
./VirusTotal -f <filename> [-v]
```

- `-f <filename>`: Specifies the path to the file for which to calculate the SHA256 checksum and scan.
- `-v`: Prints the version information.

## Examples

Calculate the SHA256 checksum and scan a file:

```shell
./VirusTotal -f /path/to/file
```

Print the version information:

```shell
./VirusTotal -v
```

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

- [VirusTotal](https://www.virustotal.com) - VirusTotal API provider