# SeeYou - Advanced Port Scanner & Service Detector

<div align="center">

```
 ___  ___  ___ _   _  ___  _   _ 
/ __|/ _ \/ _ \ | | |/ _ \| | | |
\__ \  __/  __/ |_| | (_) | |_| |
|___/\___|\___|\__, |\___/ \__,_|
                __/ |            
               |___/             v2.0
```

A powerful, feature-rich port scanner and service detector written in Go, designed for offensive security operations.

</div>

## Features

- 🚀 **High-Performance Scanning**: Multi-threaded scanning with customizable thread count
- 🎯 **Multiple Scan Types**: TCP Connect, UDP, and Stealth (SYN) scanning
- 🔍 **Service Detection**: Automatic service version detection and banner grabbing
- 🌐 **Network Support**: Scan single hosts or entire networks (CIDR notation)
- 🛡️ **Security Features**: CVE checking and service fingerprinting
- 📊 **Flexible Output**: JSON and plain text output formats
- 🎮 **Advanced Controls**: 
  - Custom port ranges
  - Random port scanning
  - Configurable timeouts and retries
  - Fragment size control
  - Ping sweep capability

## Installation

```bash
go get github.com/yourusername/seeyou
```

Or clone and build manually:

```bash
git clone https://github.com/yourusername/seeyou.git
cd seeyou
go build
```

## Usage

Basic scan:
```bash
./seeyou -host example.com
```

Scan specific ports:
```bash
./seeyou -host example.com -p 80,443,8080
```

Scan port range:
```bash
./seeyou -host example.com -p 1-1000
```

Scan all ports:
```bash
./seeyou -host example.com -all
```

Network scan:
```bash
./seeyou -host 192.168.1.0/24 -p 22,80,443
```

Advanced scan with service detection:
```bash
./seeyou -host example.com -sV -banner -fp -cve -json -out results.json
```

## Available Options

| Flag | Description | Default |
|------|-------------|---------|
| `-host` | Target host/network | Required |
| `-p` | Port range (e.g., 80,443 or 1-1000) | - |
| `-all` | Scan all ports (1-65535) | false |
| `-start` | Start port | 1 |
| `-end` | End port | 1024 |
| `-timeout` | Connection timeout | 2s |
| `-threads` | Number of concurrent threads | 100 |
| `-tcp` | Enable TCP scanning | true |
| `-udp` | Enable UDP scanning | false |
| `-banner` | Enable banner grabbing | false |
| `-stealth` | Enable stealth scanning | false |
| `-random` | Randomize port order | false |
| `-out` | Output file path | - |
| `-json` | Output in JSON format | false |
| `-v` | Verbose output | false |
| `-ping` | Ping sweep before scanning | false |
| `-sV` | Service version detection | false |
| `-fp` | OS/Service fingerprinting | false |
| `-cve` | Check for known CVEs | false |
| `-wait` | Wait time between probes | 100ms |
| `-retry` | Maximum retry attempts | 2 |
| `-frag` | Fragment size for packets | 0 |

## Output Example

```
PORT     PROTO    STATE     SERVICE    VERSION
22/tcp   open     ssh       OpenSSH_8.2p1
80/tcp   open     http      nginx/1.18.0
443/tcp  open     https     Apache/2.4.49 [CVE-2021-41773]
3306/tcp open     mysql     MySQL 8.0.26
```

## Features in Detail

### Service Detection
SeeYou automatically detects common services and their versions, including:
- Web servers (Apache, Nginx, IIS)
- SSH servers
- Database servers (MySQL, PostgreSQL)
- Mail servers (SMTP, IMAP, POP3)
- And many more...

### Security Features
- CVE checking against known vulnerabilities
- Service fingerprinting for OS and service detection
- Stealth scanning capabilities
- Configurable packet fragmentation

### Performance
- Efficient multi-threading
- Customizable scan timing
- Smart retry mechanism
- Optimized network operations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or networks.

## Author

Created and maintained by [Your Name] 