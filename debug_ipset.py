#!/usr/bin/env python3
"""
Debug ipset matching
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from test_iptables import ipset_matches, get_ipset_content

def debug_ipset():
    """Debug ipset matching for the specific case"""
    
    rule = "-A INPUT -p tcp -m tcp --dport 7022 -m set --match-set whitelist src -j ACCEPT"
    ip = "78.203.106.231"
    
    print(f"Testing rule: {rule}")
    print(f"Testing IP: {ip}")
    print("=" * 60)
    
    # Test ipset_matches with debug
    result = ipset_matches(rule, ip, debug=True)
    print(f"\nipset_matches result: {result}")
    
    # Also test get_ipset_content directly
    print("\nDirect ipset content:")
    members = get_ipset_content("whitelist")
    print(f"Whitelist members: {members}")
    
    # Manual check
    import ipaddress
    try:
        test_ip = ipaddress.ip_address(ip)
        print(f"\nManual check for {ip}:")
        for i, member in enumerate(members):
            try:
                if '/' in member:
                    network = ipaddress.ip_network(member, strict=False)
                    if test_ip in network:
                        print(f"  ✅ Found in network {member}")
                        break
                else:
                    if test_ip == ipaddress.ip_address(member):
                        print(f"  ✅ Exact match with {member}")
                        break
            except ValueError as e:
                print(f"  ❌ Error with member {member}: {e}")
        else:
            print(f"  ❌ Not found in any member")
    except ValueError as e:
        print(f"Error with test IP: {e}")

if __name__ == "__main__":
    debug_ipset()