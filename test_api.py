#!/usr/bin/env python3
"""
Simple test script to demonstrate ObserveGuard API functionality
"""

import requests
import json
import time

def test_api():
    base_url = "http://localhost:8080"

    print("🔍 Testing ObserveGuard API Server")
    print("=" * 50)

    # Test health endpoint
    try:
        print("1. Testing health endpoint...")
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("   ✅ Health check passed")
            print(f"   Response: {json.dumps(response.json(), indent=2)}")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Health check failed: {e}")
        print("   Make sure the server is running: ./build/observeguard server")
        return

    print()

    # Test version endpoint
    try:
        print("2. Testing version endpoint...")
        response = requests.get(f"{base_url}/api/v1/version", timeout=5)
        if response.status_code == 200:
            print("   ✅ Version check passed")
            print(f"   Response: {json.dumps(response.json(), indent=2)}")
        else:
            print(f"   ❌ Version check failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Version check failed: {e}")

    print()

    # Test events endpoint
    try:
        print("3. Testing events endpoint...")
        response = requests.get(f"{base_url}/api/v1/events", timeout=5)
        if response.status_code == 200:
            print("   ✅ Events endpoint working")
            data = response.json()
            if data.get('success'):
                event_count = len(data.get('data', {}).get('events', []))
                print(f"   Found {event_count} events")
            else:
                print("   No events found (expected for fresh installation)")
        else:
            print(f"   ❌ Events endpoint failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Events endpoint failed: {e}")

    print()

    # Test AI models endpoint
    try:
        print("4. Testing AI models endpoint...")
        response = requests.get(f"{base_url}/api/v1/ai/models", timeout=5)
        if response.status_code == 200:
            print("   ✅ AI models endpoint working")
            data = response.json()
            if data.get('success'):
                model_count = len(data.get('data', []))
                print(f"   Found {model_count} AI models")
        else:
            print(f"   ❌ AI models endpoint failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ AI models endpoint failed: {e}")

    print()

    # Test threats endpoint
    try:
        print("5. Testing threats endpoint...")
        response = requests.get(f"{base_url}/api/v1/threats", timeout=5)
        if response.status_code == 200:
            print("   ✅ Threats endpoint working")
            data = response.json()
            if data.get('success'):
                threat_count = len(data.get('data', []))
                print(f"   Found {threat_count} threats")
        else:
            print(f"   ❌ Threats endpoint failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Threats endpoint failed: {e}")

    print()

    # Test threat statistics endpoint
    try:
        print("6. Testing threat statistics endpoint...")
        response = requests.get(f"{base_url}/api/v1/threats/stats", timeout=5)
        if response.status_code == 200:
            print("   ✅ Threat statistics working")
            data = response.json()
            if data.get('success'):
                stats = data.get('data', {})
                print(f"   Total threats: {stats.get('total_threats', 0)}")
                print(f"   Active threats: {stats.get('active_threats', 0)}")
                severity = stats.get('by_severity', {})
                print(f"   Critical: {severity.get('critical', 0)}, High: {severity.get('high', 0)}")
        else:
            print(f"   ❌ Threat statistics failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Threat statistics failed: {e}")

    print()
    print("🎉 API Testing Complete!")
    print("\nTo test WebSocket streams:")
    print("  - Events: ws://localhost:8080/ws/events")
    print("  - Alerts: ws://localhost:8080/ws/alerts")
    print("  - Metrics: ws://localhost:8080/ws/metrics")
    print("  - Threats: ws://localhost:8080/ws/threats")

if __name__ == "__main__":
    test_api()