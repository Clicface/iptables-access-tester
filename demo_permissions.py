#!/usr/bin/env python3
"""
Demonstration: Why sudo is required for iptables

This script shows the difference between running iptables with and without root privileges.
"""

import subprocess
import os

def test_iptables_permissions():
    """Test iptables permissions with different access levels."""
    
    print("🔍 Testing iptables permissions\n")
    
    # Check current user
    current_user = os.getenv('USER', 'unknown')
    effective_uid = os.geteuid()
    
    print(f"👤 Current user: {current_user}")
    print(f"🆔 Effective UID: {effective_uid} {'(root)' if effective_uid == 0 else '(non-root)'}")
    print()
    
    # Test 1: Try iptables without sudo
    print("📋 Test 1: iptables -S INPUT (without sudo)")
    try:
        result = subprocess.run(['iptables', '-S', 'INPUT'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ Success! Rules retrieved:")
            for line in result.stdout.splitlines()[:3]:  # Show only first 3
                print(f"   {line}")
            if len(result.stdout.splitlines()) > 3:
                print(f"   ... and {len(result.stdout.splitlines()) - 3} more rules")
        else:
            print(f"❌ Failed (code {result.returncode})")
            if result.stderr:
                print(f"   Error: {result.stderr.strip()}")
    except FileNotFoundError:
        print("❌ iptables is not installed or not in PATH")
    except subprocess.TimeoutExpired:
        print("❌ Timeout - command took too long")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print()
    
    # Test 2: Explain why sudo is necessary
    print("🔐 Why sudo is required:")
    print("   • iptables controls the Linux kernel firewall")
    print("   • Firewall rules are security-sensitive information")
    print("   • Only root can access netfilter configuration")
    print("   • This prevents normal users from viewing security rules")
    print()
    
    # Test 3: Check if we can use sudo
    print("🔧 Test 3: Checking sudo access")
    try:
        result = subprocess.run(['sudo', '-n', 'iptables', '-S', 'INPUT'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ sudo works! The script can be run with sudo")
        else:
            print("❌ sudo requires password or is not configured")
    except FileNotFoundError:
        print("❌ sudo is not available")
    except subprocess.TimeoutExpired:
        print("❌ sudo timeout")
    except Exception as e:
        print(f"❌ sudo error: {e}")
    
    print()
    print("💡 Recommended solutions:")
    print("   1. Use sudo: sudo python3 test_iptables.py <ip> <port>")
    print("   2. Run as root user (not recommended)")
    print("   3. Configure specific sudo rules (advanced)")

if __name__ == "__main__":
    test_iptables_permissions()