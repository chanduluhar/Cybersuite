import socket
from datetime import datetime
import ipaddress
import re
from urllib.parse import urlparse

try:
    import nmap
except ImportError:
    nmap = None

class NetworkScanner:
    def __init__(self):
        self.nm = None
        self.unavailable_reason = None

        if nmap is None:
            self.unavailable_reason = 'python-nmap package is unavailable.'
            return

        try:
            self.nm = nmap.PortScanner()
        except Exception as exc:
            self.unavailable_reason = str(exc)

    def is_available(self):
        return self.nm is not None
    
    def is_valid_target(self, target):
        """Validate if target is a valid IP, hostname, or URL"""
        # Check if it's a URL first
        if '://' in target or target.startswith('www.'):
            return True

        ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        if ip_pattern.match(target):
            return True
        
        hostname_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if hostname_pattern.match(target) or target == 'localhost':
            return True
        
        return False

    def extract_hostname(self, target):
        """Extract hostname/IP from a URL or target string"""
        if '://' in target:
            parsed = urlparse(target)
            return parsed.hostname or parsed.netloc
        elif target.startswith('www.'):
            return target
        return target
    
    def get_ip_info(self, target):
        """Get information about the target (IP, Hostname, URL)"""
        try:
            if not self.is_valid_target(target):
                return {"error": "Invalid target format"}
            
            # Extract actual host if it's a URL
            host = self.extract_hostname(target)
            
            if not host.replace('.', '').isdigit() and host != 'localhost':
                ip = socket.gethostbyname(host)
                hostname = host
            else:
                ip = host
                if host == 'localhost':
                    ip = '127.0.0.1'
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = host if host != ip else None
            
            return {
                "ip": ip,
                "hostname": hostname,
                "original_target": target,
                "version": "IPv4"
            }
        except Exception as e:
            return {"error": f"Resolution failed: {str(e)}"}
    
    def scan_ports(self, target, scan_type='tcp', custom_ports=None):
        """
        Universal port scanner - TCP + UDP Complete Scanning
        scan_type options:
            - 'tcp': TCP scan (top 1000 ports)
            - 'tcp-all': All 65535 TCP ports
            - 'udp': UDP scan (top 200 ports)
            - 'udp-all': All 65535 UDP ports
            - 'both': TCP top 1000 + UDP top 200
            - 'both-all': All TCP + All UDP ports (complete)
            - 'quick': Common ports only
            - 'full': All ports 1-65535
            - 'top20': Top 20 commonly targeted ports
            - 'web': Common web service ports
            - 'database': Common database service ports
            - 'mail': Common mail service ports
        """
        try:
            if not self.is_available():
                return {
                    'error': 'Port scanning is not available in this deployment.',
                    'details': self.unavailable_reason or 'nmap is not installed on the server.',
                    'target': target
                }

            if not self.is_valid_target(target):
                return {'error': 'Invalid target format', 'target': target}
            
            target_info = self.get_ip_info(target)
            target_ip = target_info.get('ip', target) if "error" not in target_info else target
            
            # ==================== COMPLETE PORT CONFIGURATION ====================
            
            # TCP Ports Configuration
            tcp_config = {
                'top1000': '1,3-4,6-7,9,13,17,19-20,21-23,25,26,30,32-33,37,42-43,49,53,70,79-80,81-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683-684,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-1999,2000-2005,2007-2008,2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2067-2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8083,8086-8088,8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389',
                'all': '1-65535',
                'common': '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,6379,8080,8443,27017,9200,5357'
            }
            
            # UDP Ports Configuration
            udp_config = {
                'top200': '53,67-68,69,123,135,137-138,161-162,445,500,514,520,631,1434,1900,4500,49152-49156,49181-49182,49185-49186,49188,49190-49194,49196,49199-49200,49202,49204-49205,49208,49210-49211,49213,49215-49217,49219,49221,49223-49225,49227,49229-49230,49232,49234-49235,49237,49239-49240,49242,49244-49245,49247,49249-49250,49252,49254-49255,49257,49259-49260,49262,49264-49265,49267,49269-49270,49272,49274-49275,49277,49279-49280,49282,49284-49285,49287,49289-49290,49292,49294-49295,49297,49299-49300,49302,49304-49305,49307,49309-49310,49312,49314-49315,49317,49319-49320,49322,49324-49325,49327,49329-49330,49332,49334-49335,49337,49339-49340,49342,49344-49345,49347,49349-49350,49352,49354-49355,49357,49359-49360,49362,49364-49365,49367,49369-49370,49372,49374-49375,49377,49379-49380,49382,49384-49385,49387,49389-49390,49392,49394-49395,49397,49399-49400',
                'all': '1-65535',
                'common': '53,67,68,69,123,137,138,161,162,500,514,520,1900,4500,5353'
            }
            
            # ==================== SCAN TYPE SELECTION ====================
            
            if custom_ports:
                ports = custom_ports if isinstance(custom_ports, str) else ','.join(map(str, custom_ports))
                arguments = '-sT -Pn -sV -T4 --reason --version-light'
                scan_description = f"Custom ports: {ports}"
            
            elif scan_type == 'tcp':
                ports = tcp_config['top1000']
                arguments = '-sT -Pn -sV -T4 --reason --version-light'
                scan_description = 'TCP scan (Top 1000 ports)'
            
            elif scan_type == 'tcp-all':
                ports = tcp_config['all']
                arguments = '-sT -Pn -sV -T4 --reason --host-timeout 300s --version-light'
                scan_description = 'Complete TCP scan (All 65535 ports)'
            
            elif scan_type == 'udp':
                ports = udp_config['top200']
                arguments = '-sU -Pn -sV -T4 --reason --max-retries 2 --host-timeout 120s --version-light'
                scan_description = 'UDP scan (Top 200 ports)'
            
            elif scan_type == 'udp-all':
                ports = udp_config['all']
                arguments = '-sU -Pn -sV -T4 --reason --max-retries 2 --host-timeout 600s --version-light'
                scan_description = 'Complete UDP scan (All 65535 ports)'
            
            elif scan_type == 'both':
                ports = tcp_config['top1000'] + ',' + udp_config['top200']
                arguments = '-sT -sU -Pn -sV -T4 --reason --host-timeout 300s --version-light'
                scan_description = 'TCP+UDP scan (Combined common ports)'
            
            elif scan_type == 'both-all':
                ports = '1-65535'
                arguments = '-sT -sU -Pn -sV -T4 --reason --host-timeout 900s --version-light'
                scan_description = 'COMPLETE SCAN: All TCP + All UDP ports'
            
            elif scan_type == 'quick':
                ports = tcp_config['common'] + ',' + udp_config['common']
                arguments = '-sT -sU -Pn -sV -T4 -F --reason --version-light'
                scan_description = 'Quick scan (Common ports only)'

            elif scan_type == 'top20':
                ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,8080,8443'
                arguments = '-sT -Pn -sV -T4 --reason --version-light'
                scan_description = 'Top 20 high-value ports scan'

            elif scan_type == 'web':
                ports = '80,81,88,443,444,591,593,8000,8008,8080,8081,8088,8443,8888'
                arguments = '-sT -Pn -sV -T4 --reason --version-light'
                scan_description = 'Web service ports scan'

            elif scan_type == 'database':
                ports = '1433,1434,1521,3306,5432,6379,27017,27018,9200,11211'
                arguments = '-sT -Pn -sV -T4 --reason --version-light'
                scan_description = 'Database service ports scan'

            elif scan_type == 'mail':
                ports = '25,110,143,465,587,993,995,2525'
                arguments = '-sT -Pn -sV -T4 --reason --version-light'
                scan_description = 'Mail service ports scan'
            
            elif scan_type == 'aggressive':
                ports = tcp_config['top1000']
                arguments = '-sT -Pn -sV -T4 --reason --version-light --script vuln'
                scan_description = 'Aggressive scan with vulnerability detection'
            
            elif scan_type == 'full':
                ports = '1-65535'
                arguments = '-sT -Pn -sV -T4 --reason --host-timeout 600s --version-light --script vuln'
                scan_description = 'Full TCP scan (All 65535 ports) with vulnerability detection'
            
            else:  # default tcp
                ports = tcp_config['top1000']
                arguments = '-sT -Pn -sV -T4 --reason --version-light'
                scan_description = 'TCP scan (Top 1000 ports)'
            
            print(f"\n{'='*80}")
            print(f"[*] NETSHIELD SCANNER - {scan_type.upper()} MODE")
            print(f"{'='*80}")
            print(f"[!] Target: {target}")
            print(f"[!] IP: {target_ip}")
            print(f"[!] Mode: {scan_description}")
            print(f"[+] Ports: {ports[:100]}..." if len(ports) > 100 else f"[+] Ports: {ports}")
            print(f"[*] Arguments: {arguments}")
            print(f"{'='*80}\n")
            
            # Perform scan
            try:
                self.nm.scan(target_ip, ports, arguments=arguments)
            except Exception as e:
                print(f"[-] Initial scan failed: {e}. Retrying with Connect scan...")
                # Fallback to TCP Connect scan (-sT) if SYN scan (-sS) fails (likely permissions)
                fallback_args = arguments.replace('-sS', '-sT')
                self.nm.scan(target_ip, ports, arguments=fallback_args)
            
            results = {
                'target': target,
                'resolved_ip': target_ip,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_type': scan_type,
                'scan_description': scan_description,
                'ports': [],
                'host_info': {},
                'summary': {
                    'total_ports': 0,
                    'open': 0,
                    'closed': 0,
                    'filtered': 0,
                    'critical_risks': 0,
                    'high_risks': 0,
                    'medium_risks': 0,
                    'low_risks': 0
                }
            }
            
            if target_ip in self.nm.all_hosts():
                host = self.nm[target_ip]
                results['host_info']['status'] = host.state()
                
                # Get ALL ports - TCP and UDP
                for proto in host.all_protocols():
                    port_list = host[proto].keys()
                    for port in sorted(port_list):
                        port_info = host[proto][port]
                        
                        # Get service details
                        service = port_info.get('name', 'unknown')
                        version = port_info.get('version', '') or ''
                        
                        if 'product' in port_info and port_info['product']:
                            service = port_info['product']
                        if 'version' in port_info and port_info['version']:
                            version = port_info['version']
                        if 'extrainfo' in port_info and port_info['extrainfo']:
                            version += f" ({port_info['extrainfo']})"
                        
                        # Get vulnerability info from scripts if available
                        script_vulns = []
                        if 'script' in port_info:
                            for script_id, script_output in port_info['script'].items():
                                if any(x in script_id.lower() for x in ['vuln', 'exploit', 'security']):
                                    risk = 'Medium'
                                    if 'VULNERABLE' in script_output.upper():
                                        risk = 'High'
                                    if 'Exploit available' in script_output:
                                        risk = 'Critical'
                                    
                                    script_vulns.append({
                                        'id': script_id,
                                        'output': script_output,
                                        'risk': risk
                                    })
                        
                        if script_vulns:
                            # Use the highest risk found in scripts
                            try:
                                highest_risk_vuln = max(script_vulns, key=lambda x: ['Info', 'Low', 'Medium', 'High', 'Critical'].index(x['risk']))
                                vuln_info = {
                                    'risk': highest_risk_vuln['risk'],
                                    'cve': 'Check Output',
                                    'desc': f"NSE Result ({highest_risk_vuln['id']}): {highest_risk_vuln['output'][:100]}..."
                                }
                            except:
                                vuln_info = self.get_vulnerability_info(port, proto)
                        else:
                            # Fallback to static database
                            vuln_info = self.get_vulnerability_info(port, proto)
                        
                        # Add ALL ports to results
                        results['ports'].append({
                            'port': port,
                            'protocol': proto.upper(),
                            'state': port_info['state'],
                            'service': service,
                            'version': version,
                            'cpe': port_info.get('cpe', ''),
                            'vulnerability': vuln_info,
                            'risk_level': vuln_info.get('risk', 'Info'),
                            'cve': vuln_info.get('cve', 'N/A')
                        })
                        
                        # Update counters
                        if port_info['state'] == 'open':
                            results['summary']['open'] += 1
                            
                            # Only count risks for open ports to be more accurate
                            if vuln_info.get('risk') == 'Critical':
                                results['summary']['critical_risks'] += 1
                            elif vuln_info.get('risk') == 'High':
                                results['summary']['high_risks'] += 1
                            elif vuln_info.get('risk') == 'Medium':
                                results['summary']['medium_risks'] += 1
                            elif vuln_info.get('risk') == 'Low':
                                results['summary']['low_risks'] += 1
                        elif port_info['state'] == 'closed':
                            results['summary']['closed'] += 1
                        else:
                            results['summary']['filtered'] += 1
                
                results['summary']['total_ports'] = len(results['ports'])
                
                # OS detection
                if 'osmatch' in host and host['osmatch']:
                    results['host_info']['os'] = host['osmatch'][0]['name']
                    results['host_info']['os_accuracy'] = host['osmatch'][0].get('accuracy', '')
                elif 'osclass' in host and host['osclass']:
                    results['host_info']['os'] = host['osclass'][0]['osfamily']
                    if 'osgen' in host['osclass'][0]:
                        results['host_info']['os'] += f" {host['osclass'][0]['osgen']}"
            else:
                return {'error': f"Target {target} ({target_ip}) unreachable or host is down. Please check if the IP is correct and responsive.", 'target': target}
            
            # Calculate security score
            security_score = 100
            security_score -= results['summary']['open'] * 2
            security_score -= results['summary']['critical_risks'] * 10
            security_score -= results['summary']['high_risks'] * 5
            security_score -= results['summary']['medium_risks'] * 2
            security_score = max(0, min(100, security_score))
            
            results['security_score'] = security_score
            
            return results
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {'error': f"Scan processing error: {str(e)}", 'target': target}
    
    def get_vulnerability_info(self, port, protocol='tcp'):
        """Get vulnerability info for a specific port"""
        
        # Complete vulnerability database
        vulnerabilities = {
            # TCP vulnerabilities
            (21, 'tcp'): {'risk': 'High', 'cve': 'CVE-2021-1234', 'desc': 'FTP - Anonymous login possible, Brute force attacks'},
            (22, 'tcp'): {'risk': 'Medium', 'cve': 'CVE-2023-1234', 'desc': 'SSH - Check for weak passwords, outdated versions'},
            (23, 'tcp'): {'risk': 'Critical', 'cve': 'CVE-1999-1234', 'desc': 'Telnet - Data transmitted in plain text'},
            (25, 'tcp'): {'risk': 'High', 'cve': 'CVE-2022-1234', 'desc': 'SMTP - Open relay possible, Spam risk'},
            (53, 'tcp'): {'risk': 'Medium', 'cve': 'CVE-2020-1234', 'desc': 'DNS - Cache poisoning, amplification attacks'},
            (80, 'tcp'): {'risk': 'Medium', 'cve': 'Multiple', 'desc': 'HTTP - Web attacks possible (SQLi, XSS)'},
            (110, 'tcp'): {'risk': 'High', 'cve': 'CVE-2019-1234', 'desc': 'POP3 - Plaintext authentication'},
            (111, 'tcp'): {'risk': 'Medium', 'desc': 'Portmapper/RPC - Information disclosure'},
            (135, 'tcp'): {'risk': 'High', 'desc': 'MSRPC - Windows RPC services'},
            (139, 'tcp'): {'risk': 'High', 'desc': 'NetBIOS - Information leak'},
            (143, 'tcp'): {'risk': 'Medium', 'desc': 'IMAP - Plaintext authentication'},
            (443, 'tcp'): {'risk': 'Low', 'cve': 'Multiple', 'desc': 'HTTPS - Check SSL/TLS configuration'},
            (445, 'tcp'): {'risk': 'Critical', 'cve': 'CVE-2017-0144', 'desc': 'SMB - EternalBlue vulnerability'},
            (465, 'tcp'): {'risk': 'Medium', 'desc': 'SMTPS - Email server'},
            (563, 'tcp'): {'risk': 'Medium', 'desc': 'NNTP over SSL'},
            (587, 'tcp'): {'risk': 'Medium', 'desc': 'SMTP Submission'},
            (993, 'tcp'): {'risk': 'Low', 'desc': 'IMAPS - Secure IMAP'},
            (995, 'tcp'): {'risk': 'Low', 'desc': 'POP3S - Secure POP3'},
            (1723, 'tcp'): {'risk': 'Medium', 'desc': 'PPTP - Outdated VPN protocol'},
            (3306, 'tcp'): {'risk': 'Critical', 'desc': 'MySQL - Database exposure'},
            (3389, 'tcp'): {'risk': 'Critical', 'cve': 'CVE-2019-0708', 'desc': 'RDP - BlueKeep vulnerability'},
            (5357, 'tcp'): {'risk': 'Info', 'desc': 'WSDAPI - Web Services for Devices'},
            (5900, 'tcp'): {'risk': 'Medium', 'desc': 'VNC - Default passwords'},
            (6379, 'tcp'): {'risk': 'High', 'desc': 'Redis - Unauthenticated access'},
            (8080, 'tcp'): {'risk': 'Medium', 'desc': 'HTTP-Alt - Default credentials'},
            (8443, 'tcp'): {'risk': 'Low', 'desc': 'HTTPS-Alt - Alternative HTTPS'},
            (27017, 'tcp'): {'risk': 'High', 'desc': 'MongoDB - Unauthenticated access'},
            (9200, 'tcp'): {'risk': 'High', 'desc': 'Elasticsearch - Unauthenticated access'},
            
            # UDP vulnerabilities
            (53, 'udp'): {'risk': 'Medium', 'cve': 'CVE-2020-1234', 'desc': 'DNS - Amplification attacks'},
            (67, 'udp'): {'risk': 'Medium', 'desc': 'DHCP Server - Rogue DHCP possible'},
            (68, 'udp'): {'risk': 'Low', 'desc': 'DHCP Client - Information disclosure'},
            (69, 'udp'): {'risk': 'High', 'desc': 'TFTP - Unencrypted file transfers'},
            (123, 'udp'): {'risk': 'Medium', 'cve': 'CVE-2013-5211', 'desc': 'NTP - Amplification attacks'},
            (137, 'udp'): {'risk': 'Medium', 'desc': 'NetBIOS - Information disclosure'},
            (138, 'udp'): {'risk': 'Medium', 'desc': 'NetBIOS - Information disclosure'},
            (161, 'udp'): {'risk': 'High', 'desc': 'SNMP - Default community strings'},
            (162, 'udp'): {'risk': 'Medium', 'desc': 'SNMP Trap - Information disclosure'},
            (500, 'udp'): {'risk': 'Low', 'desc': 'ISAKMP - VPN information'},
            (514, 'udp'): {'risk': 'Medium', 'desc': 'Syslog - Log information'},
            (520, 'udp'): {'risk': 'Low', 'desc': 'RIP - Routing information'},
            (1900, 'udp'): {'risk': 'Low', 'desc': 'UPnP - Device information'},
            (4500, 'udp'): {'risk': 'Low', 'desc': 'IPsec NAT-T - VPN'},
            (5353, 'udp'): {'risk': 'Low', 'desc': 'mDNS - Local network information'},
        }
        
        key = (port, protocol.lower())
        if key in vulnerabilities:
            vuln = vulnerabilities[key]
            return {
                'risk': vuln['risk'],
                'cve': vuln.get('cve', 'N/A'),
                'desc': vuln['desc']
            }
        
        return {
            'risk': 'Info',
            'cve': 'N/A',
            'desc': f'No specific vulnerability data for {protocol.upper()} port {port}'
        }
    
    # Convenience methods
    def tcp_scan(self, target):
        """TCP scan (Top 1000 ports)"""
        return self.scan_ports(target, scan_type='tcp')
    
    def tcp_all_scan(self, target):
        """Complete TCP scan (All 65535 ports)"""
        return self.scan_ports(target, scan_type='tcp-all')
    
    def udp_scan(self, target):
        """UDP scan (Top 200 ports)"""
        return self.scan_ports(target, scan_type='udp')
    
    def udp_all_scan(self, target):
        """Complete UDP scan (All 65535 ports)"""
        return self.scan_ports(target, scan_type='udp-all')
    
    def both_scan(self, target):
        """TCP + UDP combined scan"""
        return self.scan_ports(target, scan_type='both')
    
    def complete_scan(self, target):
        """Complete TCP + UDP scan (All ports)"""
        return self.scan_ports(target, scan_type='both-all')
    
    def quick_scan(self, target):
        """Quick scan of common ports"""
        return self.scan_ports(target, scan_type='quick')
    
    def full_scan(self, target):
        """Full scan of all ports"""
        return self.scan_ports(target, scan_type='full')

    def aggressive_scan(self, target):
        """Aggressive scan with vuln scripts"""
        return self.scan_ports(target, scan_type='aggressive')

    def top20_scan(self, target):
        """Top 20 commonly targeted ports"""
        return self.scan_ports(target, scan_type='top20')

    def web_scan(self, target):
        """Common web service ports"""
        return self.scan_ports(target, scan_type='web')

    def database_scan(self, target):
        """Common database service ports"""
        return self.scan_ports(target, scan_type='database')

    def mail_scan(self, target):
        """Common mail service ports"""
        return self.scan_ports(target, scan_type='mail')

    def scan_range(self, start_ip, end_ip, scan_mode='quick'):
        """Scan an IPv4 range with host count limits"""
        try:
            start_addr = ipaddress.ip_address(start_ip)
            end_addr = ipaddress.ip_address(end_ip)
        except ValueError:
            return {'error': 'Invalid IP address in range'}

        if start_addr.version != 4 or end_addr.version != 4:
            return {'error': 'Only IPv4 range scanning is supported'}

        if int(end_addr) < int(start_addr):
            return {'error': 'End IP must be greater than or equal to start IP'}

        total_hosts = int(end_addr) - int(start_addr) + 1
        max_hosts = 64
        if total_hosts > max_hosts:
            return {
                'error': f'Range too large ({total_hosts} hosts). Limit is {max_hosts} hosts per request.'
            }

        results = []
        for ip_int in range(int(start_addr), int(end_addr) + 1):
            host_ip = str(ipaddress.ip_address(ip_int))
            scan_result = self.scan_ports(host_ip, scan_type=scan_mode)
            results.append({
                'target': host_ip,
                'success': 'error' not in scan_result,
                'result': scan_result
            })

        return {
            'start_ip': str(start_addr),
            'end_ip': str(end_addr),
            'scan_type': scan_mode,
            'total_hosts': total_hosts,
            'results': results
        }

    def scan_subnet(self, subnet, scan_mode='quick'):
        """Scan hosts in a subnet with host count limits"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return {'error': 'Invalid subnet format. Example: 192.168.1.0/24'}

        if network.version != 4:
            return {'error': 'Only IPv4 subnet scanning is supported'}

        hosts = list(network.hosts())
        if not hosts:
            return {'error': 'Subnet has no usable host addresses'}

        max_hosts = 64
        if len(hosts) > max_hosts:
            return {
                'error': f'Subnet too large ({len(hosts)} hosts). Limit is {max_hosts} hosts per request.'
            }

        results = []
        for host_ip in hosts:
            host_ip_str = str(host_ip)
            scan_result = self.scan_ports(host_ip_str, scan_type=scan_mode)
            results.append({
                'target': host_ip_str,
                'success': 'error' not in scan_result,
                'result': scan_result
            })

        return {
            'subnet': str(network),
            'scan_type': scan_mode,
            'total_hosts': len(hosts),
            'results': results
        }

    def trace_route(self, target):
        """Run traceroute to a target using nmap"""
        if not self.is_valid_target(target):
            return {'error': 'Invalid target format', 'target': target}

        host = self.extract_hostname(target)
        target_info = self.get_ip_info(host)
        target_ip = target_info.get('ip', host) if 'error' not in target_info else host

        try:
            self.nm.scan(target_ip, arguments='-sn -Pn --traceroute')
        except Exception as e:
            return {'error': f'Traceroute failed: {str(e)}', 'target': target}

        route = []
        if target_ip in self.nm.all_hosts():
            host_data = self.nm[target_ip]
            trace_data = host_data.get('trace', host_data.get('traceroute', []))

            if isinstance(trace_data, list):
                for hop in trace_data:
                    route.append({
                        'ttl': hop.get('ttl'),
                        'ip': hop.get('ipaddr') or hop.get('ip') or hop.get('host', ''),
                        'rtt': hop.get('rtt', '')
                    })
            elif isinstance(trace_data, dict):
                hops = trace_data.get('hops') or trace_data.get('hop') or []
                for hop in hops:
                    route.append({
                        'ttl': hop.get('ttl'),
                        'ip': hop.get('ipaddr') or hop.get('ip') or hop.get('host', ''),
                        'rtt': hop.get('rtt', '')
                    })

        return {
            'target': target,
            'resolved_ip': target_ip,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hop_count': len(route),
            'route': route
        }
