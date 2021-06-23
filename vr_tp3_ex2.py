
from netaddr import *
from pox.core import core
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp, echo
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
import time
import pox

log = core.getLogger()

class Router(object):
    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Buffer for packets waiting for ARP
        self.buffer = {}

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}

        # ARP Table
        self.arp_table = {}
        self.arp_table['10.0.1.1'] = 'AA:BB:CC:DD:EE:01'
        self.arp_table['10.0.2.1'] = 'AA:BB:CC:DD:EE:02'
        self.arp_table['10.0.3.1'] = 'AA:BB:CC:DD:EE:03'
        self.arp_table['10.0.4.1'] = 'AA:BB:CC:DD:EE:04'

        # Route default flows for ICMP traffic destined to Router Interfaces
        for dest in self.arp_table.keys():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_dst = IPAddr(dest)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            self.connection.send(msg)

        self.routing_table = {}
        self.routing_table['10.0.1.0/24'] = {'Port': 1, 'RouterInterface':'10.0.1.1'}
        self.routing_table['10.0.2.0/24'] = {'Port': 2, 'RouterInterface':'10.0.2.1'}
        self.routing_table['10.0.3.0/24'] = {'Port': 3, 'RouterInterface':'10.0.3.1'}
        self.routing_table['10.0.4.0/24'] = {'Port': 4, 'RouterInterface':'10.0.4.1'}

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in.pack()

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def ARP_Handler(self, packet, packet_in):
        log.debug("ARP FRAME RECEIVED FROM %s" % packet_in.in_port)

        if packet.payload.opcode == arp.REQUEST:
            log.debug("IT'S AN ARP REQUEST!")

            arp_payload = packet.payload
            arp_request_ip = str(arp_payload.protodst)
            print("Reques dst IP: " + str(arp_request_ip))
            if arp_request_ip in self.arp_table:

                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = EthAddr(self.arp_table[arp_request_ip])
                arp_reply.hwdst = arp_payload.hwsrc
                arp_reply.protosrc = arp_payload.protodst
                arp_reply.protodst = arp_payload.protosrc

                ether = ethernet()
                ether.type = ether.ARP_TYPE
                ether.src = EthAddr(self.arp_table[arp_request_ip])
                ether.dst = arp_payload.hwsrc
                ether.payload = arp_reply

                self.resend_packet(ether, packet_in.in_port)
                log.debug("ARP REPLY SENT! %s" %packet_in.in_port)
        elif packet.payload.opcode == arp.REPLY:
            log.debug("IT'S AN ARP REPLY!")

            arp_payload = packet.payload
            hwsrc = str(arp_payload.hwsrc)
            srcip = str(arp_payload.protosrc)
            if srcip not in self.arp_table:
                self.arp_table[srcip] = hwsrc
                self.mac_to_port[hwsrc] = packet_in.in_port
                log.debug("%s %s INSTALLED TO CAM TABLE" % (srcip, hwsrc))

            # If there are packets in buffer waiting to be sent out
            if srcip in self.buffer.keys():
                print ('Sending buffered ICMP!')
                out_port = self.routing_table[self.buffer[srcip]['DestinationNetwork']]['Port']
                ip_packet = self.buffer[srcip]['IP_Packet']
                etherFrame = ethernet()
                etherFrame.type = etherFrame.IP_TYPE
                etherFrame.src = EthAddr(self.arp_table[self.routing_table[self.buffer[srcip]['DestinationNetwork']]['RouterInterface']])
                etherFrame.dst = EthAddr(self.arp_table[srcip])
                etherFrame.payload = ip_packet
                self.resend_packet(etherFrame, out_port)

                msg = of.ofp_flow_mod()
                print (self.buffer[srcip]['DestinationNetwork'])
                msg.priority = 10
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_proto = ipv4.ICMP_PROTOCOL
                msg.match.set_nw_dst(self.buffer[srcip]['DestinationNetwork'])
                # msg.match.nw_dst = IPAddr(srcip)
                msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.arp_table[self.routing_table[self.buffer[srcip]['DestinationNetwork']]['RouterInterface']])))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_table[srcip])))
                msg.actions.append(of.ofp_action_output(port=out_port))
                self.connection.send(msg)
                log.debug("Flow mod for destination network %s sent!", self.buffer[srcip]['DestinationNetwork'])
                self.buffer.pop(srcip)

    def ICMP_Handler(self, packet, packet_in):
        ethernet_frame = packet
        ip_packet = packet.payload

        icmp_request_packet = ip_packet.payload

        # ICMP Echo Request (8) -> ICMP Echo Reply (0)
        if icmp_request_packet.type == 8:
            icmp_echo_reply_packet = icmp()
            icmp_echo_reply_packet.code = 0
            icmp_echo_reply_packet.type = 0
            icmp_echo_reply_packet.payload = icmp_request_packet.payload

            ip = ipv4()
            ip.srcip = ip_packet.dstip
            ip.dstip = ip_packet.srcip
            ip.protocol = ipv4.ICMP_PROTOCOL
            ip.payload = icmp_echo_reply_packet

            ether = ethernet()
            ether.type = ethernet.IP_TYPE
            ether.src = ethernet_frame.dst
            ether.dst = ethernet_frame.src
            ether.payload = ip

            self.resend_packet(ether, packet_in.in_port)
            log.debug("ICMP ECHO REPLY SENT!")

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        etherFrame = event.parsed  # This is the parsed packet data.

        if not etherFrame.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        # Add the new MAC into CAM table (content addressable memory table)
        if str(etherFrame.src) not in self.mac_to_port:
            log.debug('PacketIn: Adding %s into CAM' % str(etherFrame.src))
            self.mac_to_port[str(etherFrame.src)] = packet_in.in_port

        # ARP
        if etherFrame.type == ethernet.ARP_TYPE:
            log.debug('RECEIVED: EtherType -> ARP to %s' %etherFrame.dst)
            self.ARP_Handler(etherFrame, packet_in)
        # IP
        elif etherFrame.type == ethernet.IP_TYPE:
            log.debug('RECEIVED: EtherType -> IP from %s' %packet_in.in_port)

            # Extract IP Packet from Ethernet Frame
            ip_packet = etherFrame.payload

            # Routable?
            destination_ip = str(ip_packet.dstip)

            # checking if the packet is routable
            routable = False
            for netaddr in self.routing_table:
                destination_network = netaddr
                if IPAddress(destination_ip) in IPNetwork(destination_network):
                    routable = True
                    break
            """ -------------------  EXERCISE 2 STARTS HERE ------------------------"""
            if routable:
                log.debug('PACKET IS ROUTABLE!!!')
                # if is routable and is destined for one of the router interfaces
                if self.routing_table[str(destination_network)]['RouterInterface'] == destination_ip:
                    if ip_packet.protocol == ipv4.ICMP_PROTOCOL:
                        ICMP_Handler(etherFrame, packet_in)
                else: # else  is for one of the networks
                    # ARP if host MAC Address is not present -- the router does not know the mac addr of the ip dst
                    if destination_ip not in self.arp_table:
                        # Push frame to buffer
                        # this packet is stored untly the ARP reply arrives
                        self.buffer[destination_ip] = {'IP_Packet': ip_packet, 'DestinationNetwork': destination_network}
                        # Construct ARP Packet
                        my_arp_request = arp()
                        # set the 'opcode' var of the previous object = arp.REQUEST -- it is an ARP request after all
                        my_arp_request.opcode = arp.REQUEST
                        # set the 'protosrc' var of your arp object to the ip address of the router outgoing interface, you can use the routing table to obtain that
                        my_arp_request.protosrc = IPAddr(self.routing_table[str(destination_network)]['RouterInterface'])
                        # set the 'protodst' var of your arp object to the destination ip address
                        my_arp_request.protodst = IPAddr(destination_ip)
                        # NOTE: you can use the method IPAddr(destination_ip) to pasrse a string to an IP addr.
                        # set the 'hwsrc' var of your arp object to the mac address of the router outgoing interface, you can use the arp table to obtain that
                        my_arp_request.hwsrc = EthAddr(self.arp_table[self.routing_table[str(destination_network)]['RouterInterface']])
                        # set the 'hwdst' var of your arp object to an all zrouting_table[destination_network]['RouterInterface']eros mac address '00:00:00:00:00:00'
                        my_arp_request.hwdst = EthAddr('00:00:00:00:00:00')
                        # NOTE: you can use the method EthAddr('00:00:00:00:00:00') to pasrse a string to an MAC addr.

                        # Construct the ethernet frame
                        my_ethernet_frame = ethernet()
                        # <your_ethernet_frame_object_name>.type = ether.ARP_TYPE --- defines that this frame carries a ARP type message
                        my_ethernet_frame.type = ethernet.ARP_TYPE
                        # now we need to define the mac address for the source of this communication, the mac address of the outgoing router interface -- its the same as the one used in the arp request
                        # <your_ethernet_frame_object_name>.src =  mac address of the outgoing router interface
                        my_ethernet_frame.src = EthAddr(self.arp_table[self.routing_table[str(destination_network)]['RouterInterface']])
                        # the destination address is a broadcast mac address: 'FF:FF:FF:FF:FF:FF'
                        # <your_ethernet_frame_object_name>.dst = Broadcast mac address
                        my_ethernet_frame.dst = EthAddr('FF:FF:FF:FF:FF:FF')
                        # NOTE: you can use the method EthAddr('FF:FF:FF:FF:FF:FF') to pasrse a string to an MAC addr.

                        # Last, we attach the <your_arp_request_object> as the payload of the ethernet frame
                        # <your_ethernet_frame_object_name>.payload = <your_arp_request_object>
                        my_ethernet_frame.payload = my_arp_request
                        # Then we pass the  <your_ethernet_frame_object_name> and the  output_port to the self.resend_packet() method
                        # this will send de message to the router.
                        log.debug(self.routing_table[str(destination_network)])
                        self.resend_packet(my_ethernet_frame, self.routing_table[str(destination_network)]['Port'])

                    elif destination_ip in self.arp_table:
                        # here you must use the incoming etherFrame and change the 'src' field to be the outgoing router interface mac
                        # and change the 'dst' field to by the mac of the 'destination_ip' --- you can use the arp_table to get it
                        etherFrame.src = EthAddr(self.arp_table[self.routing_table[str(destination_network)]['RouterInterface']])
                        ehterFrame.dst = EthAddr(self.arp_table[destination_ip])
                        # you then send the frame by uncoment the following line
                        self.resend_packet(etherFrame, self.routing_table[str(destination_network)]['Port'])
            """ -------------------  EXERCISE 2 ENDS HERE ------------------------"""

            # ICMP Destination Unreachable for non-routable networks
            if not routable:
                log.debug('PACKET IS NOT ROUTABLE!')
                ethernet_frame = etherFrame
                ip_packet = etherFrame.payload
                icmp_request_packet = ip_packet.payload
                icmp_echo_reply_packet = icmp()
                icmp_echo_reply_packet.code = 0
                icmp_echo_reply_packet.type = 3
                icmp_echo_reply_packet.payload = icmp_request_packet.payload

                ip = ipv4()
                ip.srcip = ip_packet.dstip
                ip.dstip = ip_packet.srcip
                ip.protocol = ipv4.ICMP_PROTOCOL
                ip.payload = icmp_echo_reply_packet

                ether = ethernet()
                ether.type = ethernet.IP_TYPE
                ether.src = ethernet_frame.dst
                ether.dst = ethernet_frame.src
                ether.payload = ip

                self.resend_packet(ether, packet_in.in_port)
                log.debug("ICMP DESTINATION UNREACHABLE SENT")
        #else:
            # if you want to see other types of packets
            #log.debug("Not treating %s" %str(pkt.ETHERNET.ethernet.getNameForType(etherFrame.type)))


def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Router(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
