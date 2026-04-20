# Traffic Classification System using SDN (Mininet + Ryu)

## Overview
This project demonstrates a Software Defined Networking (SDN) based system that classifies network traffic using Mininet and the Ryu controller.

The system identifies and categorizes traffic into:
- TCP
- UDP
- ICMP
- Other

The controller also installs flow rules to optimize packet forwarding.

---

## How to Run

Open **two terminals**.

### Terminal 1 (Start Controller)

=>cd ~/Downloads
=>ryu-manager traffic_classifier.py


### Terminal 2 (Start Network Topology)

=>cd ~/Downloads
=>sudo python3 topology.py


After running this, you will enter the Mininet CLI:

mininet>


---

## Traffic Testing Commands (Run inside Mininet CLI)

### ICMP (Ping)
h1 ping h2

### TCP Traffic

h1 iperf -s &
h2 iperf -c 10.0.0.1


### UDP Traffic

h1 iperf -s -u &
h2 iperf -c 10.0.0.1 -u -b 10M


---

## Notes
- Always start the controller before the topology
- Only one controller should run at a time
- Use `sudo mn -c` before rerunning if needed
