"""Custom topology example

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class VrEx2Topo( Topo ):

    def build( self ):

        # Add hosts and switches

        switch = self.addSwitch( 's1' )

        host1 = self.addHost( 'h1', ip="10.0.1.100/24", defaultRoute = "via 10.0.1.1" )
        host2 = self.addHost( 'h2', ip="10.0.2.100/24", defaultRoute = "via 10.0.2.1" )
        host3 = self.addHost( 'h3', ip="10.0.3.100/24", defaultRoute = "via 10.0.3.1" )
        host4 = self.addHost( 'h4', ip="10.0.4.100/24", defaultRoute = "via 10.0.4.1" )

        # Add links
        self.addLink( switch, host1 )
        self.addLink( switch, host2 )
        self.addLink( switch, host3 )
        self.addLink( switch, host4 )

topos = { 'vrex2topo': ( lambda: VrEx2Topo() ) }
