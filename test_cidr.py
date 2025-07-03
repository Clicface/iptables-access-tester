#!/usr/bin/env python3
"""
Test CIDR matching in ipsets
"""

import ipaddress

def test_cidr_matching():
    """Test CIDR matching logic"""
    
    # Test cases: (IP to test, CIDR network, should match)
    test_cases = [
        ("192.168.1.100", "192.168.1.0/24", True),
        ("192.168.1.100", "192.168.0.0/16", True),
        ("192.168.1.100", "10.0.0.0/8", False),
        ("10.0.1.50", "10.0.0.0/16", True),
        ("10.1.1.50", "10.0.0.0/16", False),
        ("172.16.5.10", "172.16.0.0/12", True),
        ("172.32.5.10", "172.16.0.0/12", False),
        ("192.168.1.100", "192.168.1.100/32", True),  # Single IP as /32
        ("192.168.1.101", "192.168.1.100/32", False),
    ]
    
    print("Testing CIDR matching logic:")
    print("=" * 60)
    
    for test_ip, cidr, expected in test_cases:
        try:
            ip_obj = ipaddress.ip_address(test_ip)
            network_obj = ipaddress.ip_network(cidr, strict=False)
            result = ip_obj in network_obj
            
            status = "✅ PASS" if result == expected else "❌ FAIL"
            print(f"{status} {test_ip:15} in {cidr:18} = {result:5} (expected {expected})")
            
        except Exception as e:
            print(f"❌ ERROR {test_ip:15} in {cidr:18} = Error: {e}")
    
    print("\nTesting with mock ipset content:")
    print("=" * 60)
    
    # Simulate ipset content with mixed IPs and CIDRs
    mock_ipset_members = [
        "192.168.1.0/24",
        "10.0.0.0/8", 
        "172.16.5.100",
        "203.0.113.0/24",
        "198.51.100.50"
    ]
    
    test_ips = [
        "192.168.1.100",  # Should match 192.168.1.0/24
        "10.5.5.5",       # Should match 10.0.0.0/8
        "172.16.5.100",   # Should match exact IP
        "203.0.113.50",   # Should match 203.0.113.0/24
        "198.51.100.50",  # Should match exact IP
        "8.8.8.8",        # Should not match anything
    ]
    
    for test_ip in test_ips:
        matches = []
        try:
            ip_obj = ipaddress.ip_address(test_ip)
            for member in mock_ipset_members:
                try:
                    if '/' in member:
                        network = ipaddress.ip_network(member, strict=False)
                        if ip_obj in network:
                            matches.append(member)
                    else:
                        if ip_obj == ipaddress.ip_address(member):
                            matches.append(member)
                except ValueError:
                    continue
            
            if matches:
                print(f"✅ {test_ip:15} matches: {', '.join(matches)}")
            else:
                print(f"❌ {test_ip:15} matches: none")
                
        except ValueError as e:
            print(f"❌ {test_ip:15} error: {e}")

if __name__ == "__main__":
    test_cidr_matching()