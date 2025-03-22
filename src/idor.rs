use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Deserialize, Serialize};
use colored::*;
use reqwest::{Client, header};
use tokio::runtime::Runtime;

// Import types from main module
use crate::{HttpRequest, HttpResponse, HttpSender, DefaultHttpSender, REQUEST_COUNTER};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub token_type: String,
    pub user_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginCredentials {
    pub identifier: String,         // The value (email, username, etc.)
    pub identifier_field: String,   // The field name to use (email, credentials, etc.)
    pub password: String,
    #[serde(default)]
    pub device_id: Option<String>,
    pub endpoint: String,
    pub host: String,
}

// Perform login and store the token
pub fn perform_login(user_type: &str, is_impersonation: bool, config_file: Option<&str>) -> Result<(), Box<dyn Error>> {
    println!("{} Getting token for {} user...", 
        if is_impersonation { "👤" } else { "👑" },
        user_type.bright_yellow());
    
    // Override default credentials file if provided
    let credentials_file = config_file.unwrap_or("credentials.json");
    println!("Using credentials from: {}", credentials_file.bright_blue());
    
    // Try to read the credentials file
    let content = fs::read_to_string(credentials_file)
        .map_err(|e| Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Failed to read credentials file: {}", e)
        )))?;
    
    // Parse the credentials
    let creds_map: HashMap<String, LoginCredentials> = if credentials_file.ends_with(".yaml") || credentials_file.ends_with(".yml") {
        #[cfg(feature = "yaml-support")]
        {
            serde_yaml::from_str(&content)
                .map_err(|e| Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse YAML credentials: {}", e)
                )))?
        }
        #[cfg(not(feature = "yaml-support"))]
        {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "YAML support is not enabled. Use --features yaml-support when building."
            )));
        }
    } else {
        serde_json::from_str(&content)
            .map_err(|e| Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse JSON credentials: {}", e)
            )))?
    };
    
    // Get the credentials for the specified user type
    let credentials = creds_map.get(user_type)
        .ok_or_else(|| Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("User type '{}' not found in credentials file", user_type)
        )))?
        .clone();
    
    // Build login request
    let runtime = Runtime::new()?;
    
    let token = runtime.block_on(async {
        let client = Client::new();
        
        // Create login request body with configurable identifier field
        let mut login_body = HashMap::new();
        login_body.insert(credentials.identifier_field.clone(), credentials.identifier.clone());
        login_body.insert("password".to_string(), credentials.password.clone());
        
        // Only add device_id if it exists
        if let Some(device_id) = &credentials.device_id {
            login_body.insert("device_id".to_string(), device_id.clone());
        }
        
        println!("Sending login request to: {}{}", credentials.host, credentials.endpoint);
        
        // Send login request
        let response = client.post(format!("{}{}", credentials.host, credentials.endpoint))
            .json(&login_body)
            .send()
            .await
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        
        if !response.status().is_success() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Login failed: {}", response.status())
            )));
        }
        
        // Parse response
        let login_response: serde_json::Value = response.json().await
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        
        // Print response for debugging
        println!("Login response structure: {}", serde_json::to_string_pretty(&login_response).unwrap_or_default());
        
        // Extract token - specifically for your API response format
        let token = if let Some(accounts) = login_response.get("accounts") {
            if let Some(account) = accounts.as_array().and_then(|arr| arr.first()) {
                if let Some(access_token) = account.get("access_token") {
                    if let Some(token_str) = access_token.as_str() {
                        token_str.to_string()
                    } else {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "access_token is not a string"
                        )));
                    }
                } else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "No access_token found in account"
                    )));
                }
            } else {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No accounts found in array or accounts is not an array"
                )));
            }
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No accounts field found in response"
            )));
        };
        
        // Get token type (Bearer, etc.)
        let token_type = if let Some(accounts) = login_response.get("accounts") {
            if let Some(account) = accounts.as_array().and_then(|arr| arr.first()) {
                if let Some(token_type) = account.get("token_type") {
                    token_type.as_str().unwrap_or("Bearer").to_string()
                } else {
                    "Bearer".to_string()
                }
            } else {
                "Bearer".to_string()
            }
        } else {
            "Bearer".to_string()
        };
        
        Ok(AuthToken {
            token,
            token_type,
            user_type: user_type.to_string(),
        })
    })?;
    
    // Save token to file
    let filename = if is_impersonation {
        format!("itoken_{}.json", user_type)
    } else {
        format!("otoken_{}.json", user_type)
    };
    
    fs::write(&filename, serde_json::to_string_pretty(&token)?)?;
    println!("✅ Token saved to {}", filename.bright_green());
    
    Ok(())
}

// Load a token from file
pub fn load_token(user_type: &str, is_impersonation: bool) -> Result<AuthToken, Box<dyn Error>> {
    let filename = if is_impersonation {
        format!("itoken_{}.json", user_type)
    } else {
        format!("otoken_{}.json", user_type)
    };
    
    let content = fs::read_to_string(&filename)?;
    let token: AuthToken = serde_json::from_str(&content)?;
    
    Ok(token)
}

// Modify request with token
pub fn add_token_to_request(request: &mut HttpRequest, token: &AuthToken) {
    let auth_header = format!("{} {}", token.token_type, token.token);
    request.headers.insert("Authorization".to_string(), auth_header);
}

// Get all JSON files in the output directory (except response files)
pub fn get_json_files(output_dir: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut json_files = Vec::new();
    
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && 
           path.extension().map_or(false, |ext| ext == "json") && 
           !path.file_name().unwrap_or_default().to_string_lossy().ends_with("_response.json") {
            json_files.push(path);
        }
    }
    
    Ok(json_files)
}

// Make requests with a specific token and return responses
pub fn make_requests_with_token(
    files: &[PathBuf],
    token: &AuthToken,
    sender: &DefaultHttpSender,
    verbose: bool
) -> Result<HashMap<String, (HttpResponse, PathBuf)>, Box<dyn Error>> {
    let mut responses = HashMap::new();
    
    for file_path in files {
        // Read the request
        let content = fs::read_to_string(file_path)?;
        let mut request: HttpRequest = serde_json::from_str(&content)?;
        
        // Add token to request
        add_token_to_request(&mut request, token);
        
        // Get host information for output
        let host = if let Some(host) = request.headers.get("Host") {
            if host.starts_with("http://") || host.starts_with("https://") {
                host.clone()
            } else {
                format!("https://{}", host)
            }
        } else {
            "unknown_host".to_string()
        };
        
        // Send request
        match sender.send_request(&request, None, verbose) {
            Ok(response) => {
                // Create a unique key for this request
                let request_key = format!("{}{}", host, request.path);
                
                // Create filename for IDOR comparison
                let parent = file_path.parent().unwrap_or(Path::new("."));
                let stem = file_path.file_stem().unwrap_or_default().to_string_lossy();
                
                let response_filename = if token.user_type == "admin" || !token.user_type.contains("user") {
                    format!("{}_orig_response.json", stem)
                } else {
                    format!("{}_idor_response.json", stem)
                };
                
                let response_path = parent.join(&response_filename);
                
                // Save response
                let json = serde_json::to_string_pretty(&response)?;
                fs::write(&response_path, &json)?;
                
                // Get request number
                let request_num = REQUEST_COUNTER.fetch_add(1, Ordering::SeqCst);
                
                // Print info
                if !verbose {
                    // Apply colors based on response code
                    let status_color = match response.status_code {
                        200..=299 => Color::Green,
                        300..=399 => Color::Yellow,
                        400..=499 => Color::Red,
                        500..=599 => Color::Magenta,
                        _ => Color::White,
                    };
                    
                    println!("R{}: {} {} {}{} {} {} {} {}",
                        request_num,
                        file_path.display().to_string().bright_blue(),
                        request.method.bright_yellow(),
                        host.bright_green(),
                        request.path.bright_green(),
                        response.status_code.to_string().color(status_color),
                        response.status_text.color(status_color),
                        response.body.len().to_string().bright_cyan(),
                        response_path.display().to_string().bright_blue()
                    );
                }
                
                responses.insert(request_key, (response, response_path));
            },
            Err(e) => {
                eprintln!("Error sending request for {}: {}", file_path.display(), e);
            }
        }
        
        // Small delay between requests
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    Ok(responses)
}

// Compare responses and identify potential IDOR vulnerabilities
pub fn compare_responses(
    original_responses: HashMap<String, (HttpResponse, PathBuf)>,
    impersonation_responses: HashMap<String, (HttpResponse, PathBuf)>
) -> Result<(), Box<dyn Error>> {
    println!("\n🔍 IDOR Vulnerability Analysis");
    println!("============================");
    
    let mut found_vulnerabilities = 0;
    
    for (key, (orig_resp, orig_path)) in &original_responses {
        if let Some((impersonation_resp, impersonation_path)) = impersonation_responses.get(key) {
            // Check if low privilege user can access the same resource
            if impersonation_resp.status_code == 200 || impersonation_resp.status_code == 201 {
                // Potential IDOR vulnerability
                if orig_resp.status_code == 200 || orig_resp.status_code == 201 {
                    found_vulnerabilities += 1;
                    
                    println!("\n⚠️ {} Potential IDOR Vulnerability Found", "WARNING:".bright_red());
                    println!("  Endpoint: {}", key.bright_yellow());
                    println!("  Original response code: {}", orig_resp.status_code.to_string().bright_green());
                    println!("  Impersonation response code: {}", impersonation_resp.status_code.to_string().bright_green());
                    println!("  Original response file: {}", orig_path.display().to_string().bright_blue());
                    println!("  Impersonation response file: {}", impersonation_path.display().to_string().bright_blue());
                    
                    // Save report of the IDOR vulnerability
                    let report_path = format!("idor_vulnerability_{}.json", found_vulnerabilities);
                    let report = serde_json::json!({
                        "endpoint": key,
                        "original_user_response": {
                            "status_code": orig_resp.status_code,
                            "status_text": orig_resp.status_text,
                            "response_file": orig_path.display().to_string()
                        },
                        "impersonation_user_response": {
                            "status_code": impersonation_resp.status_code,
                            "status_text": impersonation_resp.status_text,
                            "response_file": impersonation_path.display().to_string()
                        },
                        "vulnerability_type": "IDOR",
                        "severity": "High",
                        "description": "Low privileged user can access the same resource as a high privileged user"
                    });
                    
                    fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;
                    println!("  Report saved to: {}", report_path.bright_green());
                }
            }
        }
    }
    
    if found_vulnerabilities == 0 {
        println!("✅ No IDOR vulnerabilities detected");
    } else {
        println!("\n⚠️ {} potential IDOR vulnerabilities found", found_vulnerabilities.to_string().bright_red());
    }
    
    Ok(())
}

// IDOR testing logic
pub fn process_idor_tests(
    directory: &str,
    original_user: &str,
    impersonation_user: &str,
    verbose: bool,
    config_file: Option<&str>
) -> Result<(), Box<dyn Error>> {
    // Ensure we have tokens for both users
    let original_token = match load_token(original_user, false) {
        Ok(token) => token,
        Err(_) => {
            println!("🔑 Original user token not found, logging in...");
            perform_login(original_user, false, config_file)?;
            load_token(original_user, false)?
        }
    };
    
    let impersonation_token = match load_token(impersonation_user, true) {
        Ok(token) => token,
        Err(_) => {
            println!("🔑 Impersonation user token not found, logging in...");
            perform_login(impersonation_user, true, config_file)?;
            load_token(impersonation_user, true)?
        }
    };
    
    println!("⚙️ Processing directory: {}", directory.bright_cyan());
    
    // First, process as normal with original user token
    println!("\n🔍 Making requests with original user token ({})", original_user.bright_yellow());
    
    // Parse and process the directory first
    crate::process_directory_parse(directory)?;
    
    // Get all processed JSON files
    let output_dir = Path::new("output");
    if !output_dir.exists() || !output_dir.is_dir() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Output directory does not exist"
        )));
    }
    
    let json_files = get_json_files(output_dir)?;
    
    // Make requests with original user token
    let sender = DefaultHttpSender;
    let original_responses = make_requests_with_token(&json_files, &original_token, &sender, verbose)?;
    
    // Reset request counter for impersonation requests
    REQUEST_COUNTER.store(1, Ordering::SeqCst);
    
    // Now make the same requests with the impersonation token
    println!("\n🕵️ Making requests with impersonation user token ({})", impersonation_user.bright_yellow());
    let impersonation_responses = make_requests_with_token(&json_files, &impersonation_token, &sender, verbose)?;
    
    // Compare results and identify potential IDOR vulnerabilities
    compare_responses(original_responses, impersonation_responses)?;
    
    Ok(())
}
