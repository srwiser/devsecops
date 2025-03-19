import pandas as pd
import re
import sys
import os

def parse_nmap_output(file_path):
    """
    Parse Nmap output and extract relevant information organized by host IP
    
    Args:
        file_path (str): Path to the Nmap output file
    Returns:
        dict: Dictionary with host IPs as keys and their scan results as values
    """
    results = {}
    current_ip = None
    current_port = None
    current_vuln = None
    in_traceroute = False
    
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    print("Starting to parse Nmap output...")
    
    for line in lines:
        line = line.strip()
        
        # Skip traceroute section
        if line.startswith('TRACEROUTE'):
            in_traceroute = True
            continue
        elif in_traceroute and not line.startswith('HOP'):
            continue
        elif line.startswith('HOP'):
            in_traceroute = False
            continue
            
        # Parse host IP - only accept IPs from Nmap scan report lines
        if line.startswith('Nmap scan report for'):
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                current_ip = ip_match.group(1)
                print(f"Found host IP: {current_ip}")
                results[current_ip] = {
                    'ports': [],
                    'vulnerabilities': []
                }
                continue
            
        if not current_ip:
            continue
            
        # Parse port information
        port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\w+)(?:\s+(.+))?', line)
        if port_match:
            port_info = {
                'Port': port_match.group(1),
                'Protocol': port_match.group(2),
                'State': port_match.group(3),
                'Service': port_match.group(4),
                'Version': port_match.group(5) if port_match.group(5) else ''
            }
            results[current_ip]['ports'].append(port_info)
            current_port = port_info
            continue
            
        # Parse vulnerability information
        if line.startswith('|'):
            if 'VULNERABLE:' in line:
                vuln_name = line.split('VULNERABLE:')[1].strip()
                vuln_info = {
                    'Port': current_port['Port'] if current_port else '',
                    'Protocol': current_port['Protocol'] if current_port else '',
                    'Vulnerability': vuln_name,
                    'Details': ''
                }
                current_vuln = vuln_info
                results[current_ip]['vulnerabilities'].append(vuln_info)
            elif current_vuln and not line.startswith('|_'):
                current_vuln['Details'] += line.strip('| ') + '\n'
    
    print(f"\nTotal hosts found: {len(results)}")
    print("Host IPs found:")
    for ip in results.keys():
        print(f"- {ip}")
    
    return results

def create_ports_sheet(results, writer):
    """Create a sheet showing ports and services for each host"""
    all_ports = {}
    
    # Collect all unique ports across hosts
    for ip, data in results.items():
        for port_info in data['ports']:
            port_key = f"{port_info['Port']}/{port_info['Protocol']}"
            if port_key not in all_ports:
                all_ports[port_key] = {'Port/Protocol': port_key}
            all_ports[port_key][ip] = f"{port_info['Service']} {port_info['Version']}".strip()
    
    # Create DataFrame
    ports_df = pd.DataFrame.from_dict(all_ports, orient='index')
    ports_df.to_excel(writer, sheet_name='Ports by Host', index=False)

def create_vulns_sheet(results, writer):
    """Create a sheet showing vulnerabilities for each host"""
    all_vulns = {}
    
    # Collect all unique vulnerabilities across hosts
    for ip, data in results.items():
        for vuln_info in data['vulnerabilities']:
            vuln_key = f"{vuln_info['Vulnerability']} (Port {vuln_info['Port']}/{vuln_info['Protocol']})"
            if vuln_key not in all_vulns:
                all_vulns[vuln_key] = {'Vulnerability': vuln_key}
            all_vulns[vuln_key][ip] = vuln_info['Details'].strip()
    
    if all_vulns:
        vulns_df = pd.DataFrame.from_dict(all_vulns, orient='index')
        vulns_df.to_excel(writer, sheet_name='Vulnerabilities by Host', index=False)

def convert_nmap_to_excel(input_path, excel_path=None):
    """
    Convert Nmap output to Excel format with hosts as columns
    
    Args:
        input_path (str): Path to the input Nmap file
        excel_path (str): Path to save the Excel file (optional)
    """
    try:
        print(f"Reading Nmap output file: {input_path}")
        results = parse_nmap_output(input_path)
        
        if not results:
            print("No host information found in the input file")
            sys.exit(1)
        
        # If excel_path is not provided, create one based on input filename
        if excel_path is None:
            excel_path = os.path.splitext(input_path)[0] + '.xlsx'
        
        # Create Excel writer
        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            create_ports_sheet(results, writer)
            create_vulns_sheet(results, writer)
            
            # Format the Excel file
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                # Adjust column widths
                for column in worksheet.columns:
                    max_length = 0
                    column = [cell for cell in column]
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = (max_length + 2)
                    worksheet.column_dimensions[column[0].column_letter].width = min(adjusted_width, 50)
        
        print(f"\nConversion completed successfully!")
        print(f"Excel file saved as: {excel_path}")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_csv_to_excel.py <nmap_output_file> [excel_file_path]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    excel_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    convert_nmap_to_excel(input_file, excel_file) 