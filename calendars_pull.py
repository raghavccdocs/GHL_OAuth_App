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
    return tokens['access_token'], tokens['locationId']

def fetch_calendars(access_token, location_id, group_id=None, show_drafted=True, page_size=50):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Version': API_VERSION,
        'Accept': 'application/json'
    }

    url = f"https://services.leadconnectorhq.com/calendars/"
    calendars = []
    page = 1

    while True:
        params = {
            'limit': page_size,
            'page': page,
            'locationId': location_id,
            'showDrafted': str(show_drafted).lower()
        }
        
        if group_id:
            params['groupId'] = group_id

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 403:
            raise Exception("403 Forbidden: Token does not have access to this location.")
        elif response.status_code != 200:
            raise Exception(f"Failed to fetch calendars: {response.status_code} - {response.text}")

        data = response.json()
        batch = data.get('calendars', [])
        calendars.extend(batch)

        if len(batch) < page_size:
            break  # No more pages

        page += 1

    log_operation("api_pull", {
        "endpoint": "/calendars",
        "count": len(calendars),
        "location_id": location_id,
        "group_id": group_id
    })
    return calendars

def export_to_csv(calendars, filename='calendars.csv'):
    if not calendars:
        print("No calendars to export.")
        return

    # Extract all unique keys from calendar objects
    all_keys = set()
    for calendar in calendars:
        all_keys.update(calendar.keys())
    all_keys = list(sorted(all_keys))

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=all_keys)
        writer.writeheader()
        for calendar in calendars:
            writer.writerow(calendar)

    print(f"Exported {len(calendars)} calendars to {filename}")
    log_operation("file_export", {"file": filename, "records": len(calendars)})

# Main execution
if __name__ == '__main__':
    try:
        token, location_id = get_valid_access_token()
        print("🔐 Access token and location ID loaded.")
        calendars = fetch_calendars(token, location_id)
        print(f"✅ Pulled {len(calendars)} calendars.")
        export_to_csv(calendars)
    except Exception as e:
        print(f"❌ Error: {e}")
        log_operation("script_error", {"reason": str(e)}) 