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
TOKEN_URL = 'https://services.leadconnectorhq.com/oauth/token' # Updated for LeadConnector (correct domain)
TOKENS_FILE = 'tokens.json' # Original tokens file name from your friend's code
AUDIT_LOG_FILE = 'data_operations.log'

# Constants for data protection
READ_ONLY_SCOPES = ['contacts.readonly', 'calendars.readonly', 'locations.readonly', 'calendars/events.readonly', 'forms.readonly']  # Only read-only scopes allowed
ALLOWED_HTTP_METHODS = ['GET']  # Only GET requests allowed
API_VERSION = '2021-07-28'  # Updated to match the contacts endpoint requirement

# API endpoints for connectivity check
API_ENDPOINTS = {
    'auth': {
        'host': 'marketplace.gohighlevel.com',
        'port': 443,
        'path': '/oauth/chooselocation',
        'method': 'GET'
    },
    'services': {
        'host': 'services.leadconnectorhq.com',  # ✅ correct
        'port': 443,
        'path': '/oauth/token',
        'method': 'POST'
    }
}

LOCATION_ID = 'lXV966Pcd9wrEyyOdDNa'

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

def     verify_api_request(method, endpoint):
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