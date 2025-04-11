# IDORbuster

A powerful tool for detecting Insecure Direct Object Reference (IDOR) vulnerabilities through automated request comparison between different privilege levels.

## Features

- Parse raw HTTP request files into a structured format
- Authenticate with different user privilege levels
- Send identical requests with different user tokens
- Automatically detect potential IDOR vulnerabilities
- Generate detailed vulnerability reports
- Color-coded terminal output for easy analysis
- Integration with [RequestCollector](https://github.com/jauharvp/RequestCollector) for capturing HTTP requests

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

## Capturing HTTP Requests

IDORbuster can analyze raw HTTP requests. You can collect these requests using [RequestCollector](https://github.com/jauharvp/RequestCollector), a companion tool designed to capture HTTP traffic for IDOR testing.

### Setting Up RequestCollector

1. **Clone and set up the RequestCollector repository**:

```bash
git clone https://github.com/jauharvp/RequestCollector.git
cd RequestCollector
cargo build --release
```

2. **Configure your browser to use RequestCollector as proxy**:
   - Set up your browser's proxy settings to point to the RequestCollector proxy (default: localhost:8080)
   - Install the RequestCollector SSL certificate in your browser's trusted certificate store

3. **Start capturing requests**:

```bash
./request_collector --output-dir /path/to/save/requests
```

4. **Browse the target application** while logged in as an admin user to capture potential IDOR endpoints

5. **Use the captured requests** with IDORbuster for vulnerability testing

For more details on RequestCollector configuration and usage, visit the [RequestCollector repository](https://github.com/jauharvp/RequestCollector).

## Testing for IDOR Vulnerabilities

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

**Complete workflow using RequestCollector**:
```bash
# Step 1: Capture requests using RequestCollector
./request_collector --output-dir ./captured_requests

# Step 2: Authenticate with both user types
./idorbuster original-login admin -c credentials.json
./idorbuster impersonation-login user -c credentials.json

# Step 3: Run full IDOR test on captured requests
./idorbuster idor -d ./captured_requests -c credentials.json
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

## RequestCollector and IDORbuster Integration

The recommended workflow for IDOR testing combines both tools:

1. Use RequestCollector to intercept HTTP requests while browsing the application as an admin
2. Configure IDORbuster with credentials for both privilege levels
3. Point IDORbuster to the directory containing the RequestCollector output
4. Run the full IDOR test to automatically detect vulnerabilities

This approach ensures comprehensive coverage of the application's API endpoints and reduces the manual effort needed to identify IDOR vulnerabilities.

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
