# IDORbuster

<img src="https://img.shields.io/badge/language-Rust-orange" alt="Rust"/> <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"/> <img src="https://img.shields.io/badge/version-0.1.0-green" alt="Version 0.1.0"/>

IDORbuster is a powerful tool for automatically detecting Insecure Direct Object Reference (IDOR) vulnerabilities in web applications by comparing responses across different privilege levels.

## Features

- Parse raw HTTP request files into structured format
- Authenticate with different user privilege levels
- Send identical requests with different user tokens
- Automatically detect potential IDOR vulnerabilities
- Generate detailed vulnerability reports
- Color-coded terminal output for easy analysis

## Installation

### Binary Releases

Download pre-built binaries from the [Releases page](https://github.com/jauharvp/IDORbuster/releases).

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jauharvp/IDORbuster.git
cd IDORbuster

# Build the tool
cargo build --release

# The binary will be available at target/release/idorbuster
```

## Configuration

Create a `credentials.json` file with your test accounts:

```json
{
  "admin": {
    "identifier": "admin@example.com",
    "identifier_field": "email",
    "password": "admin123",
    "device_id": "admin-device-12345",
    "endpoint": "/api/login",
    "host": "https://example.com"
  },
  "user": {
    "identifier": "user@example.com",
    "identifier_field": "email",
    "password": "user123",
    "device_id": "user-device-67890",
    "endpoint": "/api/login",
    "host": "https://example.com"
  }
}
```

- `identifier`: The value to use (email, username, mobile number)
- `identifier_field`: The field name used by the API (email, username, mobile, etc.)
- `device_id`: Optional device identifier
- `endpoint`: Login API endpoint
- `host`: Base URL of the target application

## Usage

### Testing for IDOR Vulnerabilities

1. **Authenticate users**:

```bash
# Authenticate as admin
./idorbuster original-login admin -c credentials.json

# Authenticate as regular user
./idorbuster impersonation-login user -c credentials.json
```

2. **Run the IDOR test**:

```bash
./idorbuster idor -d /path/to/request/files -c credentials.json
```

This will:
- Parse all HTTP files in the directory
- Make requests with the admin token
- Make the same requests with the regular user token
- Compare responses to identify IDOR vulnerabilities

### Color-Coded Output

```
R1: output/user_details.json GET https://api.example.com/users/123 200 200 OK 450 output/user_details_orig_response.json
R2: output/product_info.json GET https://api.example.com/products/456 200 200 OK 320 output/product_info_orig_response.json

⚠️ WARNING: Potential IDOR Vulnerability Found
  Endpoint: https://api.example.com/users/123
  Original response code: 200
  Impersonation response code: 200
  Original response file: output/user_details_orig_response.json
  Impersonation response file: output/user_details_idor_response.json
  Report saved to: idor_vulnerability_1.json
```

## Advanced Usage

### Individual Commands

**Parse HTTP files**:
```bash
./idorbuster parse -d /path/to/request/files
```

**Send a single request**:
```bash
./idorbuster send -f output/request.json -v
```

**Process files without testing**:
```bash
./idorbuster process -d /path/to/request/files
```

### Options

- `-c, --config`: Path to credentials file
- `-v, --verbose`: Enable verbose output
- `--original-user`: Specify original (admin) user type
- `--impersonation-user`: Specify impersonation (regular) user type

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
