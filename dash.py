#!/usr/bin/env python3
"""
Admin Dashboard for Wazuh Rules API
"""

import requests
import json
from datetime import datetime
import argparse

def get_api_stats(api_url, api_key):
    """Get deployment statistics"""
    headers = {"Authorization": f"Bearer {api_key}"}
    
    try:
        response = requests.get(
            f"{api_url}/admin/stats",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Connection error: {e}")
        return None

def list_servers(api_url, api_key):
    """List registered servers"""
    headers = {"Authorization": f"Bearer {api_key}"}
    
    try:
        response = requests.get(
            f"{api_url}/admin/servers",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Connection error: {e}")
        return None

def print_dashboard(stats, servers):
    """Print formatted dashboard"""
    print("=" * 80)
    print("WAZUH RULES API - ADMIN DASHBOARD")
    print("=" * 80)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Overall stats
    if stats:
        print("OVERALL STATISTICS")
        print("-" * 40)
        print(f"Total Deployments: {stats['stats']['total_deployments']}")
        print(f"Successful: {stats['stats']['successful']}")
        print(f"Failed: {stats['stats']['failed']}")
        print(f"Success Rate: {stats['stats']['success_rate']:.1f}%")
        print(f"Timeframe: Last {stats['stats']['timeframe_days']} days")
        print()
    
    # Server list
    if servers:
        print("REGISTERED SERVERS")
        print("-" * 40)
        print(f"{'Server ID':<20} {'Last Seen':<20} {'Deployments':<12} {'Status':<10}")
        print("-" * 40)
        
        for server in servers['servers']:
            status = "ACTIVE" if server['is_active'] else "INACTIVE"
            last_seen = server['last_seen'][:19] if server['last_seen'] else "Never"
            print(f"{server['server_id']:<20} {last_seen:<20} {server['deployment_count']:<12} {status:<10}")
        print()
    
    # Recent activity
    if stats and stats['stats'].get('daily'):
        print("RECENT ACTIVITY (Last 7 days)")
        print("-" * 40)
        print(f"{'Date':<12} {'Deployments':<12} {'Successful':<12}")
        print("-" * 40)
        
        for day in stats['stats']['daily'][:7]:
            print(f"{day['date']:<12} {day['deployments']:<12} {day['successful']:<12}")
    
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(description="Wazuh API Admin Dashboard")
    parser.add_argument("--api-url", required=True, help="API server URL")
    parser.add_argument("--api-key", required=True, help="Admin API key")
    
    args = parser.parse_args()
    
    # Get data
    stats = get_api_stats(args.api_url, args.api_key)
    servers = list_servers(args.api_url, args.api_key)
    
    # Print dashboard
    print_dashboard(stats, servers)

if __name__ == "__main__":
    main()
