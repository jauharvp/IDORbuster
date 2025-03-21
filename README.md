# IDORbuster

A powerful tool for detecting Insecure Direct Object Reference (IDOR) vulnerabilities through automated request comparison between different privilege levels.

## Features

- Parse raw HTTP request files into structured format
- Authenticate with different user privilege levels
- Send identical requests with different user tokens
- Automatically detect potential IDOR vulnerabilities
- Generate detailed vulnerability reports
- Color-coded terminal output for easy analysis

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/idorbuster.git
cd idorbuster

# Build the tool
cargo build --release
```

### Configuration

Create a `credentials.json` file with your test accounts:

```json
{
  "admin": {
    "username": "admin@example.com",
    "password": "admin123",
    "device_id": "admin-device-12345",
    "endpoint": "/api/login",
    "host": "https://example.com"
  },
  "user": {
    "username": "user@example.com",
    "password": "user123",
    "device_id": "user-device-67890",
    "endpoint": "/api/login",
    "host": "https://example.com"
  }
}
```

The `device_id` field is optional and will be included in the login request only if present.

### Testing for IDOR Vulnerabilities

1. **Get authentication tokens for the users**:

```bash
# Authenticate as admin
./idorbuster original-login admin -c credentials.json

# Authenticate as regular user
./idorbuster impersonation-login user -c credentials.json
```

2. **Process HTTP request files in a directory**:

```bash
./idorbuster process -d /path/to/request/files
```

3. **Run IDOR vulnerability testing**:

```bash
./idorbuster idor -d /path/to/request/files -c credentials.json
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `parse` | Parse HTTP files from a directory into JSON format |
| `send` | Send HTTP requests from a single JSON file |
| `process` | Parse files and send requests with current tokens |
| `original-login` | Get authentication token for high-privileged user |
| `impersonation-login` | Get authentication token for low-privileged user |
| `idor` | Run complete IDOR vulnerability test workflow |

### Example Usage

**Parse HTTP files only**:
```bash
./idorbuster parse -d /path/to/request/files
```

**Send a single request**:
```bash
./idorbuster send -f output/request.json -v
```

**Full IDOR test with custom user types**:
```bash
./idorbuster idor -d /path/to/request/files -c credentials.json --original-user admin --impersonation-user customer
```

## Output

The tool produces several types of output:

1. **Parsed requests** - JSON files in the `output/` directory
2. **Response files** - For each request, both with admin and regular user tokens
3. **Vulnerability reports** - Detailed information about detected IDOR issues

When vulnerabilities are found, they are reported in the terminal with:
- Endpoint information
- Response status codes
- File paths for full response comparison
- Vulnerability description

## How It Works

IDORbuster follows these steps to detect IDOR vulnerabilities:

1. Parse raw HTTP requests into a structured format
2. Authenticate with both high and low privileged accounts
3. Send identical requests with both privilege levels
4. Compare responses to identify cases where low-privilege users can access high-privilege resources
5. Generate reports for security teams to investigate

## Output Examples

**Terminal output**:
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

## License

[MIT License](LICENSE)
