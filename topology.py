from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI

def create_topology():
    setLogLevel('info')

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink)

    # Add controller (Ryu running separately)
    c0 = net.addController('c0',
                            controller=RemoteController,
                            ip='127.0.0.1',
                            port=6633)

    # Add switch
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # Add 3 hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')

    # Connect hosts to switch with 10Mbps bandwidth limit
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)

    net.start()
    print("\n*** Topology ready. Use CLI to run tests.")
    print("*** Try: h1 ping h2  |  h1 iperf -s & h2 iperf -c 10.0.0.1\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    create_topology()
