#!/usr/bin/env python3
"""
Test script for ipset logic debugging
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from test_iptables import get_ipset_content, ipset_matches, ip_matches

def test_ipset_logic():
    """Test the ipset matching logic with some examples"""
    
    # Test cases
    test_rules = [
        "-A INPUT -m set --match-set whitelist src -j ACCEPT",
        "-A INPUT -m set --match-set blacklist src -j DROP",
        "-A INPUT -s 192.168.1.0/24 -m set --match-set trusted src -j ACCEPT",
        "-A INPUT -m set --match-set servers src,dst -j ACCEPT",
    ]
    
    test_ip = "192.168.1.100"
    
    print(f"Testing IP: {test_ip}")
    print("=" * 50)
    
    for rule in test_rules:
        print(f"\nRule: {rule}")
        
        # Test ipset matching
        ipset_result = ipset_matches(rule, test_ip)
        print(f"  ipset_matches: {ipset_result}")
        
        # Test full IP matching
        ip_result = ip_matches(rule, test_ip)
        print(f"  ip_matches: {ip_result}")
        
        # Show ipset content if any
        import re
        ipset_patterns = [
            r'-m set --match-set (\S+) src(?:,dst)?',
            r'-m set --match-set (\S+) dst(?:,src)?',
            r'--match-set (\S+) src(?:,dst)?',
            r'--match-set (\S+) dst(?:,src)?'
        ]
        
        for pattern in ipset_patterns:
            match = re.search(pattern, rule)
            if match:
                set_name = match.group(1)
                members = get_ipset_content(set_name)
                print(f"  ipset '{set_name}' content: {members}")
                break

if __name__ == "__main__":
    test_ipset_logic()