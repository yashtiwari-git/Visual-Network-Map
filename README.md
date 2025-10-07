## Features

- Automatically discovers **active devices** on a network using:
  - **ARP ping sweep**
  - `nmap -sn` for baseline host detection
  - **ARP table reading** (`arp -a` / `ip neigh`) 
  - **Passive traffic capture** via TShark
  - **Service & OS probing** using `nmap -O -sV` for improved device type detection
- Determines **device type** (laptop, phone, NAS, router, etc.) using vendor info, hostnames, and service hints.
- Interactive **dashboard** built with HTML/Vis.js visualization.
- Allows **adding/removing nodes** visually for simulation.
- **Safe & practical**: only active devices, no personal devices exposed.
## Setup & Usage
1. Ensure you have Python 3.x installed.
2. Install required tools:
   - Nmap
   - Wireshark/TShark (for passive packet capture)
3. Run the Python scanner as administrator:
4. Place `scan.py` and `dashboard.html` in the same folder.
5. run python scan.py
6. python -m http.server 5000 on another terminal but in same folder 
7. http://127.0.0.1:5000 on browser

