import scapy.layers.l2 as scapyl2
import re


def  input_target():
    """Prompt user for target IP address or CIDR Range"""
    target = input("Enter target IP or range (e.g., 127.0.0.1/24): ").strip()

    # Validate target input format
    if not is_valid_cidr(target):
        print(f"{target} is not a valid CIDR format. Enter a valid address.")
        return None

    return target

def is_valid_cidr(cidr):
    """Validate the CIDR format."""
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$')
    return pattern.match(cidr)

def arp_scan(ip):
    """
    pdst is the Destination IP address which is passes as an argument
    The destination IP address is passed as an argument because that is where I want the arp request sent

     hwsrc *= Source MAC Address.

     psrc *= Source IP Address.

     hwdst *= Destination MAC Address.

     pdst *= Destination IP Address.

    """
    # Creating an arp request frame.
    arp_req_frame = scapyl2.ARP(pdst = ip)

    # Creating an ethernet frame. Ethernet frames contain both a src and dst MAC address
    # Use ff:ff:ff:ff:ff:ff because this is a broadcast MAC address.
    # We set a dst MAC for this because an ARP request is supposed to be broadcast to every IP in a network.
    broadcast_ether_frame = scapyl2.Ether(dst = "ff:ff:ff:ff:ff:ff")

    # This combines the arp request and the ethernet frame. It creates a new frame.
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    # Creating a variable for the Scapy srp library to store all the responses from devices on the network
    # Timeout is 1 second -- can be changed. Verbose = False is to limit the scapy provided info
    # Scapy function srp sends the ARP requests and receives them back.
    answered_list = scapyl2.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]

    result = []
    # Extract IP and MAC address for the response list.
    for _, received in answered_list:
        client_dict = {"IP": received.psrc, "MAC": received.hwsrc}
        result.append(client_dict)

    return result

def display_results(result):
    if not result:
        print("No devices found.")
        return
    print("__________________________________\nIP Address\tMAC Address\n__________________________________")
    for i in result:
        print("{}\t{}".format(i["IP"], i["MAC"]))

def main():
    target = input_target()
    if target is None:
        return

    scanned_output = arp_scan(target)
    display_results(scanned_output)

if __name__ == "__main__":
    main()
