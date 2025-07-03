#!/usr/bin/env python3
"""
IPTables Access Tester

This script tests whether a specific source IP and destination port combination
would be allowed or blocked by the current iptables INPUT chain rules.

The script analyzes iptables rules to determine if incoming TCP traffic from
a given source IP to a specific destination port would be accepted, dropped,
or rejected based on the current firewall configuration.

Author: Your Name
License: MIT
"""

import subprocess
import sys
import ipaddress
import re
import argparse

def get_rules():
    """
    Retrieve all iptables INPUT chain rules.
    
    Returns:
        list: A list of strings, each representing an iptables rule from the INPUT chain.
        
    Raises:
        subprocess.CalledProcessError: If iptables command fails (e.g., insufficient permissions).
        
    Note:
        This function requires root privileges because:
        - iptables rules contain security-sensitive information
        - Only root can access netfilter/iptables configuration
        - This prevents unauthorized users from viewing firewall rules
        
        Alternatives to avoid sudo:
        1. Add user to 'netdev' group (if supported by distribution)
        2. Use sudo rules to allow specific iptables commands
        3. Run the script as root user
        4. Use capabilities: setcap cap_net_admin+ep script.py
    """
    try:
        result = subprocess.run(['iptables', '-S', 'INPUT'], capture_output=True, text=True, check=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        if e.returncode == 4:  # Permission denied
            raise PermissionError("iptables requires root privileges. See documentation for alternatives.")
        raise

def get_ipset_content(set_name):
    """
    Retrieve the content of an ipset.
    
    Args:
        set_name (str): Name of the ipset to query.
        
    Returns:
        list: List of IP addresses/networks in the ipset, or empty list if error.
    """
    try:
        result = subprocess.run(['ipset', 'list', set_name], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        
        # Find the Members section
        members = []
        in_members = False
        for line in lines:
            if line.startswith('Members:'):
                in_members = True
                continue
            if in_members and line.strip():
                # Extract IP/network from the line (ignore timeout and other info)
                ip_part = line.strip().split()[0]
                members.append(ip_part)
        
        return members
    except subprocess.CalledProcessError:
        return []  # ipset doesn't exist or permission denied
    except FileNotFoundError:
        return []  # ipset command not available

def interface_matches(rule, ip):
    """
    Check if a rule's interface restriction matches the given IP.
    
    Args:
        rule (str): The iptables rule string to check.
        ip (str): The source IP address to test.
        
    Returns:
        bool: True if the interface matches or no interface restriction exists.
    """
    # Check for input interface restriction (-i)
    if '-i lo' in rule:
        # Loopback interface only accepts loopback IPs
        try:
            return ipaddress.ip_address(ip).is_loopback
        except:
            return False
    
    # If there's another interface specified, we assume it's not loopback
    # For external traffic simulation, we assume it comes from a non-loopback interface
    if '-i ' in rule and '-i lo' not in rule:
        # For simplicity, assume external IPs don't match specific interface rules
        # unless it's a common external interface pattern
        return not ipaddress.ip_address(ip).is_loopback
    
    # No interface restriction
    return True

def ipset_matches(rule, ip):
    """
    Check if an IP matches an ipset referenced in the rule.
    
    Args:
        rule (str): The iptables rule string to check.
        ip (str): The IP address to test.
        
    Returns:
        bool: True if IP matches the ipset or no ipset is used, False otherwise.
    """
    # Look for ipset match: -m set --match-set SETNAME src
    ipset_match = re.search(r'-m set --match-set (\S+) src', rule)
    if not ipset_match:
        return True  # No ipset used
    
    set_name = ipset_match.group(1)
    members = get_ipset_content(set_name)
    
    try:
        test_ip = ipaddress.ip_address(ip)
        for member in members:
            try:
                # Handle both single IPs and networks
                if '/' in member:
                    network = ipaddress.ip_network(member, strict=False)
                    if test_ip in network:
                        return True
                else:
                    if test_ip == ipaddress.ip_address(member):
                        return True
            except ValueError:
                continue  # Skip invalid entries
        return False
    except ValueError:
        return False

def ip_matches(rule, ip):
    """
    Check if a given IP address matches the source IP filter in an iptables rule.
    
    Args:
        rule (str): The iptables rule string to check.
        ip (str): The source IP address to test against the rule.
        
    Returns:
        bool: True if the IP matches the rule's source filter or if no source filter exists,
              False otherwise.
              
    Note:
        If the rule doesn't contain a '-s' (source) parameter, it matches all IPs.
        Supports both single IPs and CIDR notation networks.
        Also handles ipset matches.
    """
    # First check ipset matches
    if not ipset_matches(rule, ip):
        return False
    
    # Then check traditional -s source IP matches
    if '-s' not in rule:
        return True  # pas de filtre IP => match tout
    try:
        source_ip = rule.split('-s')[1].split()[0]
        return ipaddress.ip_address(ip) in ipaddress.ip_network(source_ip, strict=False)
    except Exception:
        return False

def port_matches(rule, port):
    """
    Check if a given port matches the destination port filter in an iptables rule.
    
    Args:
        rule (str): The iptables rule string to check.
        port (str or int): The destination port number to test against the rule.
        
    Returns:
        bool: True if the port matches the rule's destination port filter or if no port filter exists,
              False otherwise.
              
    Note:
        If the rule doesn't contain a '--dport' (destination port) parameter, it matches all ports.
        Currently supports single port matching only (not port ranges).
    """
    if '--dport' not in rule:
        return True  # pas de filtre port => match tout
    try:
        match = re.search(r'--dport (\d+)', rule)
        return match and int(match.group(1)) == int(port)
    except Exception:
        return False

def get_default_policy():
    """
    Retrieve the default policy for the INPUT chain.
    
    Returns:
        str: The default policy ("DROP", "ACCEPT", or "UNKNOWN" if unable to determine).
        
    Note:
        The default policy is applied when no specific rule matches the incoming packet.
        This is crucial for determining the final verdict when no explicit rules apply.
    """
    try:
        result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True, check=True)
        if "policy DROP" in result.stdout:
            return "DROP"
        if "policy ACCEPT" in result.stdout:
            return "ACCEPT"
        return "UNKNOWN"
    except subprocess.CalledProcessError:
        return "UNKNOWN"

def protocol_matches(rule, protocol="tcp"):
    """
    Check if a rule applies to the specified protocol.
    
    Args:
        rule (str): The iptables rule string to check.
        protocol (str): The protocol to test (default: "tcp").
        
    Returns:
        bool: True if the rule applies to the protocol or if no protocol is specified (applies to all).
    """
    if "-p " not in rule:
        return True  # No protocol specified = applies to all protocols
    
    # Extract protocol from rule
    try:
        protocol_match = re.search(r'-p (\w+)', rule)
        if protocol_match:
            rule_protocol = protocol_match.group(1)
            return rule_protocol == protocol
    except Exception:
        pass
    
    return False

def connection_state_matches(rule, is_new_connection=True):
    """
    Check if a rule's connection state restriction matches our test scenario.
    
    Args:
        rule (str): The iptables rule string to check.
        is_new_connection (bool): Whether we're testing a new connection (default: True).
        
    Returns:
        bool: True if the connection state matches or no state restriction exists.
    """
    if 'ctstate' not in rule and '--state' not in rule:
        return True  # No state restriction
    
    # For new connections, we only match rules that allow NEW or don't restrict state
    if is_new_connection:
        if 'NEW' in rule:
            return True
        if 'RELATED,ESTABLISHED' in rule and 'NEW' not in rule:
            return False  # This rule only applies to existing connections
    
    return True

def test_iptables(ip, port, debug=False):
    """
    Test whether incoming TCP traffic from a source IP to a destination port would be allowed.
    
    Args:
        ip (str): Source IP address to test (supports IPv4 addresses).
        port (str or int): Destination port number to test.
        debug (bool): If True, show detailed rule evaluation process.
        
    Returns:
        str: A formatted string indicating the result:
             - ✅ ACCEPTED: Traffic would be allowed by a specific rule
             - ❌ BLOCKED/REJECTED: Traffic would be blocked by a specific rule  
             - ⚠️ Default policy: No specific rule matched, shows default policy
             
    Note:
        This function analyzes TCP traffic rules and rules that apply to all protocols.
        Rules are processed in order, and the first matching rule determines the outcome.
    """
    rules = get_rules()
    debug_info = []
    
    for rule in rules:
        # Skip policy line
        if rule.startswith("-P"):
            continue
            
        # Check if rule applies to TCP traffic (either explicitly or implicitly)
        if not protocol_matches(rule, "tcp"):
            if debug:
                debug_info.append(f"❌ SKIP (protocol): {rule}")
            continue
            
        # Check each matching condition
        interface_ok = interface_matches(rule, ip)
        ip_ok = ip_matches(rule, ip)
        port_ok = port_matches(rule, port)
        state_ok = connection_state_matches(rule)
        
        if debug:
            status = "✅" if (interface_ok and ip_ok and port_ok and state_ok) else "❌"
            debug_info.append(f"{status} EVAL: {rule}")
            debug_info.append(f"    Interface: {interface_ok}, IP: {ip_ok}, Port: {port_ok}, State: {state_ok}")
            
            # Show ipset details if present
            ipset_match = re.search(r'-m set --match-set (\S+) src', rule)
            if ipset_match:
                set_name = ipset_match.group(1)
                members = get_ipset_content(set_name)
                if members:
                    debug_info.append(f"    IPset '{set_name}' contains: {', '.join(members[:5])}{'...' if len(members) > 5 else ''}")
                else:
                    debug_info.append(f"    IPset '{set_name}' is empty or not accessible")
            
        if interface_ok and ip_ok and port_ok and state_ok:
            result = ""
            if debug:
                result += "\n".join(debug_info) + "\n\n"
                
            if "-j ACCEPT" in rule:
                return result + f"✅ ACCEPTED by rule:\n{rule}"
            elif "-j DROP" in rule:
                return result + f"❌ BLOCKED by rule:\n{rule}"
            elif "-j REJECT" in rule:
                return result + f"❌ REJECTED by rule:\n{rule}"
    
    # Si aucune règle ne correspond, on applique la politique par défaut
    policy = get_default_policy()
    result = ""
    if debug:
        result += "\n".join(debug_info) + "\n\n"
    return result + f"⚠️ No matching rule found — default policy is: {policy}"

def main():
    """
    Main function that handles command-line arguments and executes the iptables test.
    """
    parser = argparse.ArgumentParser(
        description='Test whether incoming TCP traffic would be allowed by iptables rules',
        epilog='''
Examples:
  %(prog)s 192.168.1.100 22    # Test SSH access from 192.168.1.100
  %(prog)s 10.0.0.5 80         # Test HTTP access from 10.0.0.5
  %(prog)s 0.0.0.0 443         # Test HTTPS access from any IP

Why sudo is required:
  iptables rules contain security-sensitive information about your firewall.
  Only root can access netfilter/iptables configuration for security reasons.

Alternatives to sudo:
  1. Run with sudo: sudo python3 %(prog)s <source_ip> <dest_port>
  2. Add user to netdev group: sudo usermod -a -G netdev $USER
  3. Use sudo rules: echo "$USER ALL=(ALL) NOPASSWD: /sbin/iptables" | sudo tee /etc/sudoers.d/iptables
  4. Set capabilities: sudo setcap cap_net_admin+ep /usr/bin/python3
  5. Run as root user

Security note: Options 2-4 may reduce system security. Option 1 (sudo) is recommended.
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('source_ip', 
                       help='Source IP address to test (IPv4 format, e.g., 192.168.1.100)')
    
    parser.add_argument('dest_port', 
                       type=int,
                       help='Destination port number to test (1-65535)')
    
    parser.add_argument('--version', 
                       action='version', 
                       version='IPTables Access Tester 1.0')
    
    parser.add_argument('--debug', 
                       action='store_true',
                       help='Show detailed rule evaluation process')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate IP address format
    try:
        ipaddress.ip_address(args.source_ip)
    except ValueError:
        print(f"Error: '{args.source_ip}' is not a valid IP address", file=sys.stderr)
        sys.exit(1)
    
    # Validate port range
    if not (1 <= args.dest_port <= 65535):
        print(f"Error: Port {args.dest_port} is not in valid range (1-65535)", file=sys.stderr)
        sys.exit(1)
    
    # Execute the test
    try:
        result = test_iptables(args.source_ip, args.dest_port, args.debug)
        print(result)
    except PermissionError as e:
        print(f"❌ Permission Error: {e}", file=sys.stderr)
        print(f"\n💡 Solutions:", file=sys.stderr)
        print(f"   1. Run with sudo: sudo python3 {sys.argv[0]} {args.source_ip} {args.dest_port}", file=sys.stderr)
        print(f"   2. See --help for other alternatives", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"❌ iptables command failed. Make sure you have root privileges.", file=sys.stderr)
        print(f"💡 Try: sudo python3 {sys.argv[0]} {args.source_ip} {args.dest_port}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
