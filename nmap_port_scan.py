import subprocess
import sys

# target_scan_ip = input("Enter target IP address for scan")
# scan_type_argument = input("Enter the scan type argument. Ex: -sS -sT -sP or -p")

## This is the main function to run a nmap port scan ##
# Can use different arguments such as -sS -sT -sP or - p for scan type
def run_nmap_port_scan(target_scan_ip, scan_type_argument):

    # Syntax must be nmap -argument target. This is the command being applied to the cmd line
    command = ["nmap", scan_type_argument, target_scan_ip]

    try:
        # Try to execute the nmap command
        try_result = subprocess.run(command, capture_output=True, text=True, check=True)
        scan_results= try_result.stdout
        print("Scanning results are: "+scan_results)

    except subprocess.CalledProcessError as e:
        # If scan fails, then this error message will display
        # May want to make these print statements variables later for better output info
        print(f"An error has occurred while running nmap scan: {e}")
        print(f"Error Output: {e.stderr}")

# Create a thread for the function 'run_nmap_port_scan'
if __name__ == "__main__":
    ''' 
    Code below checks to ensure there are 3 arguments provided with the script: nmap, target_ip and scan_type
    If you want to use user input when running the script via cmd line then uncomment the two global variables
    (line 4 and 5) and comment out lines 33 - 40
    '''
    if len(sys.argv) != 3:
        print("Incorrect Usage. Proper usage is: Port_Scan.py <target_scan_ip> <scan_type_argument>")
        print("Example: Port_Scan.py 127.0.0.1 -sS")
        sys.exit(1)

    # Info on target / scan type from a command line argument
    target_scan_ip = sys.argv[1]
    scan_type_argument = sys.argv[2]

    # Run the nmap scan with provided target IP and Argument
    run_nmap_port_scan(target_scan_ip, scan_type_argument)

