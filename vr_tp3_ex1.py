
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

log = core.getLogger()



class ClassTest (object):
 
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def process_packet (self, packet, packet_in):

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    # self.resend_packet(packet_in, of.OFPP_ALL)

    # We add a new entry on dictionary if we don't have a match 
    # for the source MAC address
    if not self.mac_to_port.__contains__(packet.src):
      self.mac_to_port[packet.src] = packet_in.in_port

    # Then we verify the dictionary to see if we have an entry which 
    # matches with the packet's destination address
    match = of.ofp_match()
    if self.mac_to_port.__contains__(packet.dst):

      match.dl_dst = packet.dst

      self.resend_packet(packet_in, self.mac_to_port[packet.dst])

      fm = of.ofp_flow_mod()
      fm.match = match
      fm.actions.append(of.ofp_action_output(port=self.mac_to_port[packet.dst]))
      self.connection.send(fm)
    # Otherwise, we flood the packet to all ports
    else:
      self.resend_packet(packet_in, of.OFPP_ALL)

    # Note:
    # a good implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)) 
    # using buffer_id to mount the fragments again.


  

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    self.process_packet(packet, packet_in)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    ClassTest(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
