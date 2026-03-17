import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def test_investigators():
    print("\n--- Testing Investigators ---")
    # Add investigator
    investigator_data = {
        "badge_number": "ECHO-001",
        "name": "John Doe",
        "rank": "Senior Investigator"
    }
    response = requests.post(f"{BASE_URL}/investigators", json=investigator_data)
    print(f"Add Investigator: {response.status_code}, {response.json()}")
    inv_id = response.json().get('id')

    # Add another one for sorting
    investigator_data_2 = {
        "badge_number": "ECHO-002",
        "name": "Jane Smith",
        "rank": "Lead Analyst"
    }
    requests.post(f"{BASE_URL}/investigators", json=investigator_data_2)

    # Get investigators (Sorted by name)
    response = requests.get(f"{BASE_URL}/investigators?sort_by=name&order=ASC")
    print(f"Get Investigators (Asc): {response.json()}")
    
    return inv_id

def test_login(badge_number):
    print("\n--- Testing Login ---")
    login_data = {
        "badge_number": badge_number,
        "ip_address": "192.168.1.50"
    }
    response = requests.post(f"{BASE_URL}/login", json=login_data)
    print(f"Login: {response.status_code}, {response.json()}")

def test_warrants(inv_id):
    print("\n--- Testing Warrants ---")
    warrant_data = {
        "investigator_id": inv_id,
        "case_id": "CASE-2024-001",
        "target_ip": "10.0.0.5",
        "warrant_number": "W-998877",
        "expiry_date": "2024-12-31"
    }
    response = requests.post(f"{BASE_URL}/warrants", json=warrant_data)
    print(f"Add Warrant: {response.status_code}, {response.json()}")

    # Get warrants
    response = requests.get(f"{BASE_URL}/warrants?sort_by=expiry_date&order=DESC")
    print(f"Get Warrants (Desc): {response.json()}")

if __name__ == "__main__":
    try:
        # Check if server is running
        requests.get(BASE_URL)
        
        inv_id = test_investigators()
        test_login("ECHO-001")
        if inv_id:
            test_warrants(inv_id)
            
    except requests.exceptions.ConnectionError:
        print("Error: API server is not running on 127.0.0.1:8000")
