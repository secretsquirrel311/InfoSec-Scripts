# InfoSec-Scripts
Scripts to automate basic InfoSec tasks

## NOTE
Any information (code, articles, Proof of Concept, etc) contained wihtin this repo are _Strictly_ for educational purposes or AUTHORIZED professional use cases. I do not condone or authorize any and all information contained here to be used for illiict activity.  
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
### 21OCT24: 
Added a basic python script to run an nmap scan using a target IP address and scan type arguments. Additional functionality is planned to be added into the script. See description on the commit for more info.  

### 27MAR25: 
Added a comprehensive NMAP Network Reconaissance script. This script contains 6 Nmap functions for common tasks. The script provides a 'pretty' interface for the user allowing them to select which type of scan they want to execute or exit out. The code itself contains validation for IP addresses, port argument, and IP address with subnet mask. This is a major improvement on my coding skills as I typically do not include any validation. Additionally, I added error handling to each function as well to handle and output an errors during runtime. Overall, definitely improving my coding knowledge and skill. I still used outside resources, but mainly to clean up my code, simplify, or provide better readability. Eventually I will get to the point of not needing outside resources for stuff like this. 

### 28MAR25
Added a network sniffer script. This script takes a target IP address with a subnet mask and sends an ARP request to every device in range. The script then returns all the IP and MAC addresses. The libraries used are Scapy (scapy.layers.l2 specifically) and re for the IP address validation. I did follow along with a guide as I have not used the Scapy library prior. The guide I used is: https://dev.to/dharmil18/writing-a-network-scanner-using-python-3b80. However, I did change some parts from this guide to better suite my workflow and how I prefer the logic to work. Additionally, I am planning on adding in multithreading to improve performance for scanning larger ranges or subnets, provide a function to save the scan results in csv format for further analysis, and finally I would liked to add a Queue to scan multiple IPs concurrently. 
