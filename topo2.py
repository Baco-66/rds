from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def topology():
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSSwitch)
    # criar objetos das coisas

    # Area 0
    h01 = net.addHost('h01', ip='192.168.0.10/24', mac='00:00:00:00:00:01', defaultroute='192.168.0.254')
    h02 = net.addHost('h02', ip='192.168.0.11/24', mac='00:00:00:00:00:02', defaultroute='192.168.0.254')
    h03 = net.addHost('h03', ip='192.168.0.12/24', mac='00:00:00:00:00:03', defaultroute='192.168.0.254')
    s0 = net.addSwitch('s0', protocols='OpenFlow13')
    net.addLink(h01, s0)
    net.addLink(h02, s0)
    net.addLink(h03, s0)

    # Area 1
    h11 = net.addHost('h11', ip='192.168.1.10/24',  mac='00:00:00:00:01:01', defaultroute='192.168.1.254')
    h12 = net.addHost('h12', ip='192.168.1.11/24',  mac='00:00:00:00:01:02', defaultroute='192.168.1.254')
    h13 = net.addHost('h13', ip='192.168.1.12/24',  mac='00:00:00:00:01:03', defaultroute='192.168.1.254')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    net.addLink(h11, s1)
    net.addLink(h12, s1)
    net.addLink(h13, s1)
    
    # Area 2
    h21 = net.addHost('h21', ip='192.168.2.10/24',  mac='00:00:00:00:02:01', defaultroute='192.168.2.254')
    h22 = net.addHost('h22', ip='192.168.2.11/24',  mac='00:00:00:00:02:02', defaultroute='192.168.2.254')
    h23 = net.addHost('h23', ip='192.168.2.12/24',  mac='00:00:00:00:02:03', defaultroute='192.168.2.254')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    net.addLink(h21, s2)
    net.addLink(h22, s2)
    net.addLink(h23, s2)
    
    
    # Router
    r1 = net.addSwitch('r1', protocols='OpenFlow13') # definir 3 macs
    
    #n = net.get(r1)
    #n.setMAC(mac='00:00:00:00:00:04',intf=1)


    net.addLink(s0, r1)
    net.addLink(s1, r1)
    net.addLink(s2, r1)


    c6 = net.addController( 'c6',ip='127.0.0.1', port=6633, protocols='OpenFlow13')
    c7 = net.addController( 'c7',ip='127.0.0.1', port=6653, protocols='OpenFlow13')
   
    net.build()
    c6.start()
    c7.start()
    s1.start( [c6] )
    s0.start( [c6] )
    s2.start( [c6] )
    r1.start( [c7] )
    
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    for sw in net.switches:
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
