import os
import json
import requests
import csv
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

TOKENS_FILE = 'tokens.json'
LOG_FILE = 'data_operations.log'
API_VERSION = '2021-04-15'

# Utilities

def load_tokens():
    try:
        with open(TOKENS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load token: {e}")
        return None

def log_operation(op_type, details):
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'operation_type': op_type,
        'details': details
    }
    with open(LOG_FILE, 'a') as f:
        json.dump(log_entry, f)
        f.write('\n')

def get_valid_access_token():
    tokens = load_tokens()
    if not tokens:
        raise Exception("Token file not found. Please authorize first.")
    return tokens['access_token']

def fetch_contacts(access_token, page_size=50):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Version': API_VERSION,
        'Accept': 'application/json'
    }

    url = f"https://services.leadconnectorhq.com/contacts/"
    contacts = []
    page = 1

    while True:
        params = {
            'limit': page_size,
            'page': page
        }

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 403:
            raise Exception("403 Forbidden: Token does not have access to this location.")
        elif response.status_code != 200:
            raise Exception(f"Failed to fetch contacts: {response.status_code} - {response.text}")

        data = response.json()
        batch = data.get('contacts', [])
        contacts.extend(batch)

        if len(batch) < page_size:
            break  # No more pages

        page += 1

    log_operation("api_pull", {"endpoint": "/contacts", "count": len(contacts)})
    return contacts

def export_to_csv(contacts, filename='contacts.csv'):
    if not contacts:
        print("No contacts to export.")
        return

    # Extract all unique keys from contact objects
    all_keys = set()
    for contact in contacts:
        all_keys.update(contact.keys())
    all_keys = list(sorted(all_keys))

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=all_keys)
        writer.writeheader()
        for contact in contacts:
            writer.writerow(contact)

    print(f"Exported {len(contacts)} contacts to {filename}")
    log_operation("file_export", {"file": filename, "records": len(contacts)})

# Main execution
if __name__ == '__main__':
    try:
        token = get_valid_access_token()
        print("🔐 Access token loaded.")
        contacts = fetch_contacts(token)
        print(f"✅ Pulled {len(contacts)} contacts.")
        export_to_csv(contacts)
    except Exception as e:
        print(f"❌ Error: {e}")
        log_operation("script_error", {"reason": str(e)})
