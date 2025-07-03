#!/usr/bin/env python3
"""
Simple test to isolate the ipset issue
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from test_iptables import ipset_matches, ip_matches

def test_simple():
    """Simple test"""
    
    rule = "-A INPUT -p tcp -m tcp --dport 7022 -m set --match-set whitelist src -j ACCEPT"
    ip = "78.203.106.231"
    
    print(f"Rule: {rule}")
    print(f"IP: {ip}")
    print("=" * 60)
    
    # Test ipset_matches
    print("Testing ipset_matches:")
    result1 = ipset_matches(rule, ip, debug=True)
    print(f"ipset_matches result: {result1}")
    
    print("\nTesting ip_matches:")
    result2 = ip_matches(rule, ip)
    print(f"ip_matches result: {result2}")

if __name__ == "__main__":
    test_simple()