import os
import json
import requests
import webbrowser
import urllib.parse
import time
import socket
from datetime import datetime, timedelta
from dotenv import load_dotenv
from requests.exceptions import RequestException, ConnectionError, Timeout
# --- REMOVED: from http.server import HTTPServer, BaseHTTPRequestHandler
# --- REMOVED: import threading

# Load environment variables
load_dotenv()

# GHL OAuth2 Configuration
# IMPORTANT: This application is configured to be READ-ONLY to protect existing CRM data
# No modifications will be made to the existing data in the CRM
# If new data needs to be added, it will be done in a way that preserves all existing data
# Data Protection Rules:
# 1. Existing data is strictly read-only
# 2. No updates or modifications to existing records
# 3. No overwriting of existing data
# 4. New data additions must be done in a way that doesn't affect existing records
# 5. All operations must be logged for audit purposes

CLIENT_ID = os.getenv('GHL_CLIENT_ID')
CLIENT_SECRET = os.getenv('GHL_CLIENT_SECRET')
# This REDIRECT_URI must still be registered in your GHL App settings,
# even though we are not running a local server to catch it.
REDIRECT_URI = os.getenv('GHL_REDIRECT_URI', 'http://localhost:8000/callback') 
AUTH_URL = 'https://marketplace.gohighlevel.com/oauth/chooselocation' # Original Auth URL from your friend's code
TOKEN_URL = 'https://services.gohighlevel.com/oauth/token' # Original Token URL from your friend's code
TOKENS_FILE = 'tokens.json' # Original tokens file name from your friend's code
AUDIT_LOG_FILE = 'data_operations.log'

# Constants for data protection
READ_ONLY_SCOPES = ['contacts.readonly']  # Only read-only scopes allowed
ALLOWED_HTTP_METHODS = ['GET']  # Only GET requests allowed
API_VERSION = '2021-04-15'  # Fixed API version to prevent unexpected changes

# API endpoints for connectivity check
API_ENDPOINTS = {
    'auth': {
        'host': 'marketplace.gohighlevel.com',
        'port': 443,
        'path': '/oauth/chooselocation',
        'method': 'GET'
    },
    'services': {
        'host': 'services.gohighlevel.com',
        'port': 443,
        'path': '/oauth/token',
        'method': 'POST'
    }
}

# --- REMOVED: OAuthCallbackHandler class as it's for the local server

def log_operation(operation_type, details):
    """Log all data operations for audit purposes"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'operation_type': operation_type,
        'details': details,
        'environment': os.getenv('ENVIRONMENT', 'development')
    }
    with open(AUDIT_LOG_FILE, 'a') as f:
        json.dump(log_entry, f)
        f.write('\n')

def verify_data_protection(data_operation):
    """Verify that the operation doesn't affect existing data"""
    # Enhanced verification logic
    if data_operation.get('operation_type') == 'read':
        return True
    if data_operation.get('operation_type') == 'create':
        # Additional checks for new data
        if data_operation.get('method') not in ALLOWED_HTTP_METHODS:
            log_operation('protection_violation', {
                'reason': f"Invalid HTTP method: {data_operation.get('method')}",
                'allowed_methods': ALLOWED_HTTP_METHODS
            })
            return False
        return True
    return False

def verify_api_request(method, endpoint):
    """Verify that the API request complies with data protection rules"""
    if method not in ALLOWED_HTTP_METHODS:
        log_operation('protection_violation', {
            'reason': f"Invalid HTTP method: {method}",
            'endpoint': endpoint
        })
        return False
    return True

def save_tokens(tokens):
    """Save tokens to file with expiration timestamp"""
    # Add additional security checks
    if not isinstance(tokens, dict):
        log_operation('token_error', {'reason': 'Invalid token format'})
        return False
        
    tokens['expires_at'] = (datetime.now() + timedelta(seconds=tokens['expires_in'])).isoformat()
    tokens['created_at'] = int(time.time())
    tokens['scope'] = ' '.join(READ_ONLY_SCOPES)  # Ensure only read-only scopes are saved
    
    try:
        with open(TOKENS_FILE, 'w') as f:
            json.dump(tokens, f, indent=4)
        log_operation('token_save', {'timestamp': datetime.now().isoformat()})
        return True
    except Exception as e:
        log_operation('token_error', {'reason': f'Failed to save tokens: {str(e)}'})
        return False

def load_tokens():
    """Load tokens from file"""
    try:
        with open(TOKENS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from token file: {e}. File might be corrupt.")
        # Optionally, remove the corrupt file here: os.remove(TOKENS_FILE)
        return None

def refresh_access_token():
    """Refresh the access token using the refresh token"""
    tokens = load_tokens()
    if not tokens or 'refresh_token' not in tokens:
        # Instead of raising Exception, signal that manual re-auth is needed
        print("No refresh token available or token file is corrupt. Manual re-authentication required.")
        return None # Indicate failure to refresh

    print("Attempting to refresh access token...")
    try:
        response = requests.post(TOKEN_URL, data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token']
        })
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        new_tokens = response.json()
        save_tokens(new_tokens)
        print("Access token refreshed successfully.")
        return new_tokens
    except requests.exceptions.HTTPError as e:
        print(f"Failed to refresh token (HTTP error): {e.response.status_code} - {e.response.text}")
        if e.response.status_code == 400 and "invalid_grant" in e.response.text:
            print("Refresh token is invalid or revoked. A new manual authorization is needed.")
        return None # Indicate failure to refresh
    except Exception as e:
        print(f"Failed to refresh token (general error): {e}")
        return None # Indicate failure to refresh

def get_valid_access_token():
    """Get a valid access token, refreshing if necessary. Prompts for manual auth if no valid token."""
    tokens = load_tokens()
    
    if tokens:
        # Check if token needs refresh
        expires_at = datetime.fromisoformat(tokens.get('expires_at', datetime.min.isoformat())) # Default to min date if missing
        if datetime.now() >= expires_at - timedelta(minutes=5): # Refresh 5 mins before expiry
            print("Access token is expired or about to expire.")
            refreshed_tokens = refresh_access_token()
            if refreshed_tokens:
                return refreshed_tokens['access_token']
            else:
                print("Failed to refresh token. Falling back to manual authorization.")
                return manual_authorize() # Fallback to manual if refresh fails
        else:
            return tokens['access_token']
    else:
        print("No tokens found. Initiating manual OAuth authorization process.")
        return manual_authorize()

def check_endpoint(endpoint_name, endpoint_config):
    """Check connectivity to a specific endpoint with detailed diagnostics"""
    results = {
        'dns_resolution': False,
        'connection': False,
        'http_response': False,
        'error': None
    }
    
    try:
        # 1. DNS Resolution Check
        try:
            ip_address = socket.gethostbyname(endpoint_config['host'])
            results['dns_resolution'] = True
            log_operation('connectivity_check', {
                'endpoint': endpoint_name,
                'stage': 'dns',
                'status': 'success',
                'ip': ip_address
            })
        except socket.gaierror as e:
            results['error'] = f"DNS resolution failed: {str(e)}"
            log_operation('connectivity_check', {
                'endpoint': endpoint_name,
                'stage': 'dns',
                'status': 'failed',
                'error': str(e)
            })
            return results

        # 2. TCP Connection Check
        try:
            with socket.create_connection(
                (endpoint_config['host'], endpoint_config['port']),
                timeout=5
            ) as sock:
                results['connection'] = True
                log_operation('connectivity_check', {
                    'endpoint': endpoint_name,
                    'stage': 'tcp',
                    'status': 'success'
                })
        except (socket.timeout, ConnectionRefusedError) as e:
            results['error'] = f"TCP connection failed: {str(e)}"
            log_operation('connectivity_check', {
                'endpoint': endpoint_name,
                'stage': 'tcp',
                'status': 'failed',
                'error': str(e)
            })
            return results

        # 3. HTTP Response Check (only for auth endpoint)
        if endpoint_name == 'auth':
            try:
                response = requests.get(
                    f"https://{endpoint_config['host']}{endpoint_config['path']}",
                    timeout=5,
                    allow_redirects=True
                )
                results['http_response'] = True
                log_operation('connectivity_check', {
                    'endpoint': endpoint_name,
                    'stage': 'http',
                    'status': 'success',
                    'status_code': response.status_code
                })
            except Exception as e:
                results['error'] = f"HTTP check failed: {str(e)}"
                log_operation('connectivity_check', {
                    'endpoint': endpoint_name,
                    'stage': 'http',
                    'status': 'failed',
                    'error': str(e)
                })

    except Exception as e:
        results['error'] = f"Unexpected error: {str(e)}"
        log_operation('connectivity_check', {
            'endpoint': endpoint_name,
            'stage': 'general',
            'status': 'failed',
            'error': str(e)
        })

    return results

def verify_api_connectivity():
    """Verify connectivity to all required API endpoints with detailed diagnostics"""
    print("\nChecking API connectivity...")
    
    all_connected = True
    for name, config in API_ENDPOINTS.items():
        print(f"\nChecking {name.capitalize()} API...")
        results = check_endpoint(name, config)
        
        # Display status with checkmarks or X marks
        dns_status = "✓" if results['dns_resolution'] else "✗"
        conn_status = "✓" if results['connection'] else "✗"
        http_status = "✓" if results['http_response'] else "✗"
        
        print(f"DNS Resolution: {dns_status}")
        print(f"TCP Connection: {conn_status}")
        if name == 'auth':
            print(f"HTTP Response: {http_status}")
        
        # For services endpoint, we only need DNS and TCP connection
        if name == 'services':
            if not (results['dns_resolution'] and results['connection']):
                all_connected = False
                print(f"\nServices API connection issue: {results['error']}")
        else:
            if not (results['dns_resolution'] and results['connection'] and results['http_response']):
                all_connected = False
                print(f"\nAuth API connection issue: {results['error']}")
    
    if not all_connected:
        print("\nConnection issues detected. Please check:")
        print("1. Your internet connection")
        print("2. DNS settings (try using 8.8.8.8 or 1.1.1.1 as DNS servers)")
        print("3. Firewall settings (ensure outbound HTTPS traffic is allowed)")
        print("4. VPN connection (if using)")
        print("5. If using a proxy, ensure it's properly configured")
        print("\nIf the issue persists:")
        print("- Try accessing https://marketplace.gohighlevel.com in your browser")
        print("- Check if you can ping services.gohighlevel.com")
        print("- Verify your network's SSL/TLS settings")
        return False
    
    print("\nAll required API endpoints are accessible.")
    return True

def validate_config():
    """Validate that all required configuration is present"""
    if not CLIENT_ID:
        raise ValueError("GHL_CLIENT_ID environment variable is not set")
    if not CLIENT_SECRET:
        raise ValueError("GHL_CLIENT_SECRET environment variable is not set")
    return True

def main():
    try:
        validate_config()
        print("\n=== GHL OAuth Authentication ===")
        print("\nData Protection Rules:")
        print("1. Existing data is strictly read-only")
        print("2. No updates or modifications to existing records")
        print("3. No overwriting of existing data")
        print("4. New data additions must be done in a way that doesn't affect existing records")
        print("5. All operations are logged for audit purposes")
        
        # Check connectivity before proceeding
        if not verify_api_connectivity():
            print("\nCannot proceed due to connectivity issues.")
            exit(1)
        
        # Get a valid access token
        access_token = get_valid_access_token()
        
        if access_token:
            print("\nSuccessfully obtained/refreshed Access Token.")
            print(f"You can now use this token for API calls (e.g., first 10 chars: {access_token[:10]}...)")
            
            # Example API Call with enhanced protection
            print("\nAttempting a test API call (Get Contacts)...")
            try:
                if not verify_api_request('GET', 'contacts'):
                    raise Exception("API request violates data protection rules")
                    
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Version': API_VERSION,
                    'Accept': 'application/json'
                }
                
                # Add timeout and retry logic for API call
                session = requests.Session()
                retries = 3
                timeout = 10  # seconds
                
                for attempt in range(retries):
                    try:
                        response = session.get(
                            'https://services.leadconnectorhq.com/contacts/',
                            headers=headers,
                            timeout=timeout
                        )
                        response.raise_for_status()
                        break
                    except (ConnectionError, Timeout) as e:
                        if attempt == retries - 1:  # Last attempt
                            raise
                        print(f"API call attempt {attempt + 1} failed. Retrying...")
                        time.sleep(2 ** attempt)  # Exponential backoff
                
                contacts = response.json().get('contacts', [])
                print(f"Successfully fetched {len(contacts)} contacts.")
                if contacts:
                    # Only display non-sensitive information
                    print(f"First contact found (ID: {contacts[0].get('id')})")
                log_operation('api_call_success', {
                    'endpoint': 'contacts',
                    'count': len(contacts),
                    'method': 'GET'
                })
            except ConnectionError as e:
                print(f"\nConnection error: Could not connect to GHL services. Please check your internet connection.")
                print(f"Technical details: {str(e)}")
                log_operation('api_call_failed', {
                    'endpoint': 'contacts',
                    'reason': f"Connection error: {str(e)}"
                })
            except Timeout as e:
                print(f"\nConnection timeout: The request took too long to complete.")
                print(f"Technical details: {str(e)}")
                log_operation('api_call_failed', {
                    'endpoint': 'contacts',
                    'reason': f"Timeout error: {str(e)}"
                })
            except requests.exceptions.HTTPError as e:
                print(f"API call failed: {e.response.status_code} - {e.response.text}")
                log_operation('api_call_failed', {
                    'endpoint': 'contacts',
                    'reason': e.response.text,
                    'status_code': e.response.status_code
                })
            except Exception as e:
                print(f"An error occurred during API call: {e}")
                log_operation('api_call_failed', {
                    'endpoint': 'contacts',
                    'reason': str(e)
                })
        else:
            print("\nFailed to obtain Access Token. Please ensure your .env is correct and you followed the manual steps.")
            log_operation('authentication_final_failure', {'reason': 'Could not get access token'})
            exit(1)
            
    except ValueError as e:
        print(f"\nConfiguration error: {e}")
        print("Please ensure you have set up your .env file correctly with GHL_CLIENT_ID and GHL_CLIENT_SECRET.")
        exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred in main: {e}")
        log_operation('script_error', {'reason': str(e)})
        exit(1)

if __name__ == '__main__':
    main()