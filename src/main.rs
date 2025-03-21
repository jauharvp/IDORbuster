use clap::{Parser, Subcommand};
use colored::*;
use reqwest::{header, Client, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, read_dir, DirEntry};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::runtime::Runtime;

// Import IDOR module
mod idor;

// Global counter for request numbering
static REQUEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

// SOLID:
// - Single Responsibility Principle: Each struct and function has a single responsibility
// - Open/Closed Principle: Code is open for extension (traits) but closed for modification
// - Liskov Substitution Principle: Using traits for different parser implementations
// - Interface Segregation Principle: Smaller, focused traits
// - Dependency Inversion Principle: High-level modules depend on abstractions

// Command line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about = "HTTP request parser tool")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse HTTP files from a directory
    Parse {
        #[clap(short, long, value_name = "DIRECTORY")]
        directory: String,
    },
    /// Send HTTP requests from JSON files
    Send {
        #[clap(short, long, value_name = "JSON_FILE")]
        file: String,

        #[clap(short, long, value_name = "TARGET_HOST")]
        target: Option<String>,

        #[clap(short, long, action)]
        verbose: bool,
    },
    /// Process all HTTP files in a directory (parse, send, and save responses)
    Process {
        #[clap(short, long, value_name = "DIRECTORY")]
        directory: String,

        #[clap(short, long, value_name = "TARGET_HOST")]
        target: Option<String>,

        #[clap(short, long, action)]
        verbose: bool,
    },
    /// Get token for original (high-privileged) user
    OriginalLogin {
        #[clap(value_name = "USERTYPE")]
        usertype: String,

        #[clap(short = 'c', long = "config", value_name = "CONFIG_FILE")]
        config: Option<String>,
    },
    /// Get token for impersonation (low-privileged) user
    ImpersonationLogin {
        #[clap(value_name = "USERTYPE")]
        usertype: String,

        #[clap(short = 'c', long = "config", value_name = "CONFIG_FILE")]
        config: Option<String>,
    },
    /// Test for IDOR vulnerabilities
    Idor {
        #[clap(short, long, value_name = "DIRECTORY")]
        directory: String,

        #[clap(long, value_name = "ORIGINAL_USER")]
        original_user: Option<String>,

        #[clap(long, value_name = "IMPERSONATION_USER")]
        impersonation_user: Option<String>,

        #[clap(short, long, action)]
        verbose: bool,
    },
}

// Define the structure for an HTTP request
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

// Define a trait for file reading
trait FileReader {
    fn read_files(&self, dir_path: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>>;
}

// Default implementation of FileReader
struct DefaultFileReader;

impl FileReader for DefaultFileReader {
    fn read_files(&self, dir_path: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
        let mut file_paths = Vec::new();

        if !dir_path.is_dir() {
            return Err(format!("{} is not a directory", dir_path.display()).into());
        }

        let entries = read_dir(dir_path)?;

        for entry in entries {
            let entry: DirEntry = entry?;
            let path = entry.path();

            if path.is_file() {
                file_paths.push(path);
            }
        }

        Ok(file_paths)
    }
}

// Define a trait for HTTP parsing
trait HttpParser {
    fn parse_http(&self, content: &str) -> Result<HttpRequest, Box<dyn Error>>;
    fn is_http_format(&self, content: &str) -> bool;
}

// Default implementation of HttpParser
struct DefaultHttpParser;

impl HttpParser for DefaultHttpParser {
    fn parse_http(&self, content: &str) -> Result<HttpRequest, Box<dyn Error>> {
        let mut lines = content.lines();

        // Parse the request line (e.g., "GET /path HTTP/1.1")
        let request_line = lines.next().ok_or("Empty HTTP content")?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(format!("Invalid request line: {}", request_line).into());
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let version = parts[2].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut current_line;

        loop {
            current_line = lines.next();

            match current_line {
                Some(line) if !line.is_empty() => {
                    let parts: Vec<&str> = line.splitn(2, ": ").collect();
                    if parts.len() == 2 {
                        headers.insert(parts[0].to_string(), parts[1].to_string());
                    }
                }
                _ => break,
            }
        }

        // Parse body (everything after the empty line)
        let mut body = String::new();
        for line in lines {
            body.push_str(line);
            body.push('\n');
        }

        let body_option = if body.is_empty() {
            None
        } else {
            Some(body.trim().to_string())
        };

        Ok(HttpRequest {
            method,
            path,
            version,
            headers,
            body: body_option,
        })
    }

    fn is_http_format(&self, content: &str) -> bool {
        if content.is_empty() {
            return false;
        }

        let first_line = content.lines().next().unwrap_or("");

        // Check if first line matches HTTP method pattern (e.g., "GET /path HTTP/1.1")
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() != 3 {
            return false;
        }

        let method = parts[0];
        let version = parts[2];

        // Check for common HTTP methods
        let valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        let is_valid_method = valid_methods.contains(&method);

        // Check for HTTP version
        let is_valid_version = version.starts_with("HTTP/");

        is_valid_method && is_valid_version
    }
}

// Define a trait for HTTP request sending
pub trait HttpSender {
    fn send_request(
        &self,
        request: &HttpRequest,
        target_host: Option<&str>,
        verbose: bool,
    ) -> Result<HttpResponse, Box<dyn Error>>;
}

// Default implementation of HttpSender
pub struct DefaultHttpSender;

impl HttpSender for DefaultHttpSender {
    fn send_request(
        &self,
        request: &HttpRequest,
        target_host: Option<&str>,
        verbose: bool,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        let runtime = Runtime::new()?;

        runtime.block_on(async {
            let client = Client::new();

            // Determine method
            let method = match request.method.as_str() {
                "GET" => Method::GET,
                "POST" => Method::POST,
                "PUT" => Method::PUT,
                "DELETE" => Method::DELETE,
                "PATCH" => Method::PATCH,
                "HEAD" => Method::HEAD,
                "OPTIONS" => Method::OPTIONS,
                _ => return Err(format!("Unsupported HTTP method: {}", request.method).into()),
            };

            // Determine URL
            let host = if let Some(target) = target_host {
                // Use target host if provided (will override Host header)
                target.to_string()
            } else if let Some(host) = request.headers.get("Host") {
                // Use Host header from the request
                if host.starts_with("http://") || host.starts_with("https://") {
                    host.clone()
                } else {
                    // Add HTTPS by default if protocol is not specified
                    format!("https://{}", host)
                }
            } else {
                // No host information available
                return Err(
                    "No Host header found in the request. Use -t to specify a target host.".into(),
                );
            };

            let url = format!("{}{}", host, request.path);

            if verbose {
                println!("Sending request to: {}", url);
                println!("Target: {}", host);
            }

            // Build request with headers
            let mut req_builder = client.request(method, &url);

            // Create a header map to properly pass all headers
            let mut header_map = header::HeaderMap::new();

            for (name, value) in &request.headers {
                // Skip headers that shouldn't be sent
                if name == "Host" && target_host.is_some() {
                    // Skip host header if target host is provided
                    continue;
                }

                if name == "Content-Length" {
                    // Skip Content-Length as reqwest will calculate it
                    continue;
                }

                // Try to parse the header name and value
                if let Ok(header_name) = header::HeaderName::from_bytes(name.as_bytes()) {
                    if let Ok(header_value) = header::HeaderValue::from_str(value) {
                        header_map.insert(header_name, header_value);
                        if verbose {
                            println!("Adding header: {} = {}", name, value);
                        }
                    } else if verbose {
                        println!("Warning: Could not parse header value for: {}", name);
                    }
                } else if verbose {
                    println!("Warning: Invalid header name: {}", name);
                }
            }

            // Add all the headers at once
            req_builder = req_builder.headers(header_map);

            // Add body if present
            if let Some(body) = &request.body {
                if verbose {
                    println!("Request body: {}", body);
                }
                req_builder = req_builder.body(body.clone());
            }

            // Send the request
            let response = req_builder.send().await?;

            // Build the response structure
            let status = response.status();
            let status_code = status.as_u16();
            let status_text = status.to_string();

            if verbose {
                println!("Response status: {}", status);
                println!("Response headers:");
                for (name, value) in response.headers() {
                    println!(
                        "  {}: {}",
                        name,
                        value.to_str().unwrap_or("Invalid header value")
                    );
                }
            }

            // Extract response headers
            let mut response_headers = HashMap::new();
            for (name, value) in response.headers() {
                response_headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
            }

            // Get response body
            let body = response.text().await?;

            if verbose {
                println!("Response body: {}", body);
            }

            // Create the response structure
            let http_response = HttpResponse {
                status_code,
                status_text,
                headers: response_headers,
                body,
            };

            Ok(http_response)
        })
    }
}

// Service to process HTTP files
struct HttpFileProcessor<R: FileReader, P: HttpParser> {
    file_reader: R,
    http_parser: P,
}

impl<R: FileReader, P: HttpParser> HttpFileProcessor<R, P> {
    fn new(file_reader: R, http_parser: P) -> Self {
        Self {
            file_reader,
            http_parser,
        }
    }

    fn process_directory(
        &self,
        dir_path: &str,
    ) -> Result<Vec<(PathBuf, HttpRequest)>, Box<dyn Error>> {
        let path = Path::new(dir_path);
        let file_paths = self.file_reader.read_files(path)?;

        let mut http_requests = Vec::new();

        for file_path in file_paths {
            match self.process_file(&file_path) {
                Ok(request) => http_requests.push((file_path.clone(), request)),
                Err(e) => eprintln!("Error processing file {}: {}", file_path.display(), e),
            }
        }

        Ok(http_requests)
    }

    fn process_file(&self, file_path: &Path) -> Result<HttpRequest, Box<dyn Error>> {
        let content = fs::read_to_string(file_path)?;

        if !self.http_parser.is_http_format(&content) {
            return Err(format!("File {} is not in HTTP format", file_path.display()).into());
        }

        self.http_parser.parse_http(&content)
    }
}

// Repository trait for saving parsed data
trait HttpRequestRepository {
    fn save(&self, file_path: &Path, request: &HttpRequest) -> Result<(), Box<dyn Error>>;
}

// JSON implementation of the repository
struct JsonHttpRequestRepository {
    output_dir: String,
}

impl JsonHttpRequestRepository {
    fn new(output_dir: String) -> Self {
        Self { output_dir }
    }

    fn generate_output_path(&self, input_path: &Path) -> PathBuf {
        let file_stem = input_path.file_stem().unwrap_or_default();
        let output_filename = format!("{}.json", file_stem.to_string_lossy());

        let mut output_path = PathBuf::from(&self.output_dir);
        if !output_path.exists() {
            fs::create_dir_all(&output_path).unwrap_or_else(|_| {
                eprintln!("Could not create output directory, using current directory");
                output_path = PathBuf::from(".");
            });
        }

        output_path.push(output_filename);
        output_path
    }
}

impl HttpRequestRepository for JsonHttpRequestRepository {
    fn save(&self, file_path: &Path, request: &HttpRequest) -> Result<(), Box<dyn Error>> {
        let output_path = self.generate_output_path(file_path);
        let json = serde_json::to_string_pretty(request)?;
        fs::write(&output_path, json)?;
        println!("Saved to {}", output_path.display());
        Ok(())
    }
}

// Service to send HTTP requests from JSON files
struct HttpRequestSender<P: HttpSender> {
    http_sender: P,
}

impl<P: HttpSender> HttpRequestSender<P> {
    fn new(http_sender: P) -> Self {
        Self { http_sender }
    }

    fn send_from_file(
        &self,
        file_path: &str,
        target_host: Option<&str>,
        verbose: bool,
    ) -> Result<(), Box<dyn Error>> {
        // Read and parse the JSON file
        let json_content = fs::read_to_string(file_path)?;
        let request: HttpRequest = serde_json::from_str(&json_content)?;

        // Get host information for output
        let host = if let Some(target) = target_host {
            target.to_string()
        } else if let Some(host) = request.headers.get("Host") {
            if host.starts_with("http://") || host.starts_with("https://") {
                host.clone()
            } else {
                format!("https://{}", host)
            }
        } else {
            "unknown_host".to_string()
        };

        if verbose {
            println!("Sending {} request to {}", request.method, request.path);
        }

        let response = self
            .http_sender
            .send_request(&request, target_host, verbose)?;

        // Save the response to a JSON file
        let path = Path::new(file_path);
        let parent = path.parent().unwrap_or(Path::new("."));
        let file_stem = path.file_stem().unwrap_or_default();

        // Create response filename - append "_response" to the original filename
        let response_filename = format!("{}_{}.json", file_stem.to_string_lossy(), "response");
        let response_path = parent.join(response_filename);

        // Serialize and save the response
        let json = serde_json::to_string_pretty(&response)?;
        fs::write(&response_path, json)?;

        // Get request number and increment counter
        let request_num = REQUEST_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Print color-coded single-line output with request number
        if !verbose {
            // Apply different colors based on response code
            let status_color = match response.status_code {
                200..=299 => Color::Green,   // Success
                300..=399 => Color::Yellow,  // Redirection
                400..=499 => Color::Red,     // Client error
                500..=599 => Color::Magenta, // Server error
                _ => Color::White,           // Unknown
            };

            // Format the output with colored components
            let output = format!(
                "R{}: {} {} {}{} {} {} {} {}",
                request_num,
                file_path.bright_blue(),
                request.method.bright_yellow(),
                host.bright_green(),
                request.path.bright_green(),
                response.status_code.to_string().color(status_color),
                response.status_text.color(status_color),
                response.body.len().to_string().bright_cyan(),
                response_path.display().to_string().bright_blue()
            );

            println!("{}", output);
        } else {
            println!("Response saved to {}", response_path.display());
        }

        Ok(())
    }
}

// Function to parse HTTP files in a directory
pub fn process_directory_parse(directory: &str) -> Result<(), Box<dyn Error>> {
    // Create the processor with dependencies
    let file_reader = DefaultFileReader;
    let http_parser = DefaultHttpParser;
    let processor = HttpFileProcessor::new(file_reader, http_parser);

    // Process the directory
    let http_requests = processor.process_directory(directory)?;

    // Save the results
    println!("Processed {} HTTP request files", http_requests.len());

    // Output directory - default to output/
    let output_dir = "output".to_string();

    // Create repository
    let repository = JsonHttpRequestRepository::new(output_dir);

    // Save each request with its original filename but .json extension
    for (i, (file_path, request)) in http_requests.iter().enumerate() {
        // Save individual file
        repository.save(file_path, request)?;

        // Print summary to console
        println!(
            "Request #{}: {} {} (headers: {}) - file: {}",
            i + 1,
            request.method,
            request.path,
            request.headers.len(),
            file_path.display()
        );
    }

    Ok(())
}

// Function to process directory, parse files, send requests and save responses
fn process_directory_full(
    directory: &str,
    target_host: Option<&str>,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    // Step 1: Parse HTTP files and save as JSON
    process_directory_parse(directory)?;

    if verbose {
        println!("\nParsing completed. Now sending requests...\n");
    }

    // Step 2: Read the output directory and send requests for each JSON file
    let output_dir = Path::new("output");
    if !output_dir.exists() || !output_dir.is_dir() {
        return Err("Output directory does not exist or is not a directory".into());
    }

    let sender = DefaultHttpSender;
    let request_sender = HttpRequestSender::new(sender);

    let entries = fs::read_dir(output_dir)?;
    let mut sent_count = 0;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Only process .json files that don't end with _response.json
        if path.is_file()
            && path.extension().map_or(false, |ext| ext == "json")
            && !path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .ends_with("_response.json")
        {
            if verbose {
                println!("Processing file: {}", path.display());
            }

            // Send the request and save response
            match request_sender.send_from_file(path.to_str().unwrap(), target_host, verbose) {
                Ok(_) => sent_count += 1,
                Err(e) => eprintln!("Error sending request for {}: {}", path.display(), e),
            }

            // Add a small delay between requests to avoid overwhelming the server
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    if verbose {
        println!("\nCompleted sending {} requests", sent_count);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize colored crate
    colored::control::set_override(true);

    // Reset request counter
    REQUEST_COUNTER.store(1, Ordering::SeqCst);

    // Parse command line arguments
    let args = Args::parse();

    match &args.command {
        Commands::Parse { directory } => {
            // Process the directory for parsing only
            process_directory_parse(directory)?;
        }
        Commands::Send {
            file,
            target,
            verbose,
        } => {
            // Create HTTP sender
            let sender = DefaultHttpSender;
            let request_sender = HttpRequestSender::new(sender);

            // Send the request
            request_sender.send_from_file(file, target.as_deref(), *verbose)?;
        }
        Commands::Process {
            directory,
            target,
            verbose,
        } => {
            // Process the directory for parsing, sending, and saving responses
            process_directory_full(directory, target.as_deref(), *verbose)?;
        }
        Commands::OriginalLogin { usertype, config } => {
            // Perform original user login
            idor::perform_login(usertype, false, None)?;
        }
        Commands::ImpersonationLogin { usertype, config } => {
            // Perform impersonation user login
            idor::perform_login(usertype, true, None)?;
        }
        Commands::Idor {
            directory,
            original_user,
            impersonation_user,
            verbose,
        } => {
            // Use default user types if not specified
            let original = original_user.as_deref().unwrap_or("admin");
            let impersonation = impersonation_user.as_deref().unwrap_or("user");

            // Run IDOR tests
            idor::process_idor_tests(directory, original, impersonation, *verbose, None)?;
        }
    }

    Ok(())
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_format_valid() {
        let parser = DefaultHttpParser;
        let content = "POST /api/Address/ HTTP/1.1\nHost: example.com\n\n{\"key\":\"value\"}";
        assert!(parser.is_http_format(content));
    }

    #[test]
    fn test_is_http_format_invalid() {
        let parser = DefaultHttpParser;
        let content = "This is not an HTTP request";
        assert!(!parser.is_http_format(content));
    }

    #[test]
    fn test_parse_http_request() {
        let parser = DefaultHttpParser;
        let content = "POST /api/endpoint HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"key\":\"value\"}";

        let result = parser.parse_http(content).unwrap();

        assert_eq!(result.method, "POST");
        assert_eq!(result.path, "/api/endpoint");
        assert_eq!(result.version, "HTTP/1.1");
        assert_eq!(result.headers.get("Host"), Some(&"example.com".to_string()));
        assert_eq!(result.body, Some("{\"key\":\"value\"}".to_string()));
    }
}
