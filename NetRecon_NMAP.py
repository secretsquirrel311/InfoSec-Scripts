import nmap
import re

# Add nmap executable path
nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe",]

# Create a new instance of the PortScanner Class
nm = nmap.PortScanner(nmap_search_path=nmap_path)

### Beginning of validator functions ###

def is_valid_ip(ip):
    """Check if the IP address is valid."""
    # Checks the validity of the IP address (format) by using regex
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return pattern.match(ip) is not None

def is_valid_port_specification(spec):
    """Validate the port specification format for nmap."""
    pattern = re.compile(r'^(T:|U:)?(\d{1,5}|\d{1,5}-\d{1,5})(,(T:|U:)?(\d{1,5}|\d{1,5}-\d{1,5}))*$')
    return pattern.match(spec) is not None

def is_valid_ip_with_subnet(ip_with_subnet):
    """Validate the IP address with the subnet mask format"""
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$')
    return pattern.match(ip_with_subnet) is not None

### End of validator functions ###



### BEGINNING OF NMAP FUNCTIONS ###

# Function 1 - scan a single host while specifying a specific port
def single_host_scan():
    ip = input("Enter target IP address: ").strip() # User enters IP address and strips extra space
    if not is_valid_ip(ip):
        print("Invalid IP address format. Please enter a valid IP")
        return # Exit function if IP is invalid

    args = input("What arguments do you want to add? Ex: 80 or 21,22-443 ").strip() # Gets user input arguments

    # Validate the user input for args
    if '-p' in args:
        ports = args.split('-p')[1].strip() # Extract the port specification
        if not is_valid_port_specification(ports):
            print("Invalid port specification. Use a format such as: 22 or 22-443 or 22,31,50-100")
            return # Exit function if port is invalid

    try:
        print(f"Scanning {ip} with arguments: {args}...") # Feedback to the user
        nm.scan(ip, args) # Execute the scan
        scan_info_results = nm.scaninfo() # Retrieve scan results
        all_host_results = nm.all_hosts() # Get all hosts found in the scan

        # Pretty print of results
        print("Scan Info Results:")
        print(scan_info_results)
        print("\nHost Results:")
        for host in all_host_results:
            print(f"Host: {host} - State: {nm[host].state()}") # Display each host's state

    except Exception as e:
        print(f"An Error occurred: {e}") # Catch any exceptions and print the error

# Function 2 - performs an icmp scan (ping) against an ip with subnet mask
def single_host_icmp_scan():
    ip_w_subnet_mask = input("Please enter the ip address with subnet mask. Ex: 127.0.0.1/24: ")
    if not is_valid_ip_with_subnet(ip_w_subnet_mask):
        print("Invalid format. Enter a valid IP address with a subnet mask (ex: 127.0.0.1/24")
        return # Exit function if IP is invalid

    args = '-sn'

    try:
        print(f"Scanning network {ip_w_subnet_mask} with argument: {args}...")
        nm.scan(hosts=ip_w_subnet_mask, arguments=args) # Performs the scan

        # Print results
        print("Scan results: ")
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print('Host: %s - State: %s' % (host, nm[host].state())) # Provide the host's state
            else:
                print('Host: %s - State: %s' % (host, nm[host].state())) # Show other hosts' states
    except Exception as e:
        print(f"An error occurred: {e}") # Catch and print any errors

# Function 3 - Performs a stealth scan against an IP
def single_host_stealth_scan_syn():
    ip = input("Enter the IP you want to stealthily scan: ").strip()
    if not is_valid_ip(ip):
        print("Invalid IP address. Please enter a valid IP.")
        return # Exit function if IP is invalid

    args = '-sS'

    try:
        print(f"Scanning {ip} with argument: {args}...")
        nm.scan(ip, arguments=args)

        # Print results
        print("Scan results: ")
        found_open_ports = False
        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                port_list = nm[host][protocol].keys()
                for port in port_list:
                    if nm[host][protocol][port]['state'] == 'open':
                        found_open_ports = True
                        service_name = nm[host][protocol][port]['name'] # Get the service name
                        # Print open ports, protocol and service name
                        print('Port: %s is open on %s protocol - Service: %s' % (port, protocol, service_name))

        if not found_open_ports:
            print("No open ports found.")

    except Exception as e:
        print(f"An error occurred: {e}") # Print exception error message

# Function 4 - tcp connect stealth scan of single target
def single_host_tcp_connect_stealth():
    ip = input("Please enter the ip address to scan: ")
    if not is_valid_ip(ip):
        print(f"{ip} is an invalid format. Please enter correct IP address.")
        return

    args = '-sT -sV' # Can remove -sV if version detection is not needed

    try:
        print(f"Scanning {ip} with argument: {args}...")
        nm.scan(ip, arguments=args)

        print("Scan results are: ")
        found_open_ports = False
        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                port_list = nm[host][protocol].keys()
                for port in port_list:
                    if nm[host][protocol][port]['state'] == 'open':
                        found_open_ports = True
                        service_name = nm[host][protocol][port]['name']
                        print(f'Open Port: {port}/{protocol} - Service: {service_name}')

        if not found_open_ports:
            print("No open ports found.")

    except Exception as e:
        print(f"An error occurred: {e}")

# Function 5 - Service and version detection for a target's open ports
def service_and_version_detection():
    ip = input("Enter the ip address to scan: ").strip()
    if not is_valid_ip(ip):
        print(f"{ip} is not valid. Please enter a different IP.")
        return

    args = '-sV'

    try:
        print(f"Scanning {ip} with argument: {args}...")
        nm.scan(ip, arguments=args)

        print("Scan results are: ")
        found_open_ports = False
        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                port_list = nm[host][protocol].keys()
                for port in port_list:
                    if nm[host][protocol][port]['state'] == 'open':
                        found_open_ports = True
                        service = nm[host][protocol][port]['name']
                        version = nm[host][protocol][port]['version']
                        print(f"Port: {port} (Protocol: {protocol}) - Service: {service}, Version: {version}")

        if not found_open_ports:
            print("No open ports found.")

    except Exception as e:
        print(f"An error occurred: {e}")

# Function 6 - Gather operating system details for a target
def os_fingerprinting():
    ip = input("Enter the ip address to scan: ").strip()
    if not is_valid_ip(ip):
        print(f"{ip} is invalid. Please enter a valid IP address.")
        return

    args = '-O'

    try:
        print(f"Scanning {ip} with argument: {args}...")
        nm.scan(ip, arguments=args)

        if not nm.all_hosts(): # Echk if there are hosts found
            print(f"No hosts found for the IP: {ip}.")
            return

        found_os = False
        for host in nm.all_hosts():
            if 'osclass' in nm[host]:
                found_os = True
                for osclass in nm[host]['osclass']:
                    os_family = osclass['osfamily']
                    os_version = osclass.get('osversion',  'N/A') # Get OS version or default to N/A
                    print(f'OS Family: {os_family}, Version: {os_version}')
            else:
                print(f"No OS detected for host: {host}.")

        if not found_os: # If no OS was found at all
            print("No operating systems detected.")

    except Exception as e:
        print(f"An error occured: {e}")

### END OF NMAP FUNCTIONS ###


### MAIN FUNCTION TO PROVIDE OPTIONS TO USER DEPENDING ON THEIR NEEDS ###

def main():
    while True:
        choice = input("Please look over the options and select the scan you want. Or press 0 to exit.\n"
                       "1. Single host scan\n"
                       "2. Single host ICMP scan\n"
                       "3. Single host stealth scan\n"
                       "4. Single host tcp connect stealth scan\n"
                       "5. Service and version detection\n"
                       "6. OS fingerprinting\n"
                       "0. Exit\n"
                       "\n"
                       "Selection: ")
        if choice == "1":
            single_host_scan()
        elif choice == "2":
            single_host_icmp_scan()
        elif choice == "3":
            single_host_stealth_scan_syn()
        elif choice == "4":
            single_host_tcp_connect_stealth()
        elif choice == "5":
            service_and_version_detection()
        elif choice == "6":
            os_fingerprinting()
        elif choice == "0":
            break
        else:
            print("Invalid entry.")


if __name__ == "__main__":
    main()
