from typing import Tuple, Dict

from pyshark.packet.fields import LayerFieldsContainer
from pyshark.packet.packet import Packet
from .nodes import TwoTupleUnidirectionalNode

def add_to_counter(counter, key, val=1):
    if key in counter:
        counter[key] += val
    else:
        counter[key] = val

class AnubisFG:
    '''
    Class stores information in memory and generate features of flows.

    It can update the stored information from new packets and extract features
    from fluxes from this stored information.

    It keeps the information on two dictionaries, one for the two-tuple flow
    (IP Source, IP Destination) and one for the 5-tuple flow (IP Source, Port
    Source, IP Destination, Port Destination, Protocol). Optionally it can
    store information on the bidirection flows.

    Parameters
    ----------
    bidirectional: `bool`
        Wheter or not to consider the bidirectional flow (default True).
    only_twotuple: `bool`
        Wheter or not to store information of only the two-tuple flows
        (default False).
    only_fivetuple: `bool`
        Wheter or not to store information of only the five-tuple flows
        (default False).

    Attributes
    ----------
    memory_twotup: `dict`
        The dictionary with the information of the flows. Has key (IP Source,
        IP Destination), a tuple with two
        pyshark.packet.fields.LayerFieldsContainer's, and value 
        TwoTupleUnidirectionalNode object.

    Examples
    --------
    >>> afg = AnubisFG()

    Creates a AnubisFG object.

    >>> afg.update(packet)

    Updates the memories with a packet.

    >>> afg.generate_features(five_tuple=(ip_src, port_src, ip_dst, port_dst,
                                          protocol))
    list_of_features

    Extract the features of both the two-tuple and the five-tuple flows with the
    stored information.

    '''

    def __init__(self,
                 memory_twotup: Dict[Tuple[LayerFieldsContainer,
                                           LayerFieldsContainer],
                                     TwoTupleUnidirectionalNode] = None):
        if memory_twotup is None:
            self.memory_twotup = dict()
        else:
            msg = 'AssertionError: memory_twotup must be of type ' \
                  'Dict[Tuple[LayerFieldsContainer, LayerFieldsContainer], ' \
                  'TwoTupleUnidirectionalNode]'
            assert isinstance(memory_twotup, dict), msg
            for item in memory_twotup.items():
                assert isinstance(item[0], tuple), msg
                assert isinstance(item[0][0], LayerFieldsContainer), msg
                assert isinstance(item[0][1], LayerFieldsContainer), msg
                assert isinstance(item[1], TwoTupleUnidirectionalNode), msg
            self.memory_twotup = memory_twotup

    def _update_twotupleuni(self, packet: Packet):
        """TODO
        Usage
        -----
        capture = pyshark.FileCapture('tests/data/test_100_rows.pcap')
        for packet in capture:
            update(packet)
        """
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            timestamp = packet.sniff_time
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
            protocol = packet.transport_layer
            length = packet.length
            hdr_legth = packet.ip.hdr_length
        except:
            return
        # Only works for tcp packets
        try:
            ack = packet.tcp.flags_ack
            cwr = packet.tcp.flags_cwr
            ecn = packet.tcp.flags_ecn
            fin = packet.tcp.flags_fin
            res = packet.tcp.flags_res
            syn = packet.tcp.flags_syn
            urg = packet.tcp.flags_urg
            psh = packet.tcp.flags_push
        except:
            ack = 0
            cwr = 0
            ecn = 0
            fin = 0
            res = 0
            syn = 0
            urg = 0
            psh = 0
        key = (ip_src, ip_dst)
        if key in self.memory_twotup:
            self.memory_twotup[key].lst_timestamp = timestamp
            self.memory_twotup[key].set_src_ports.add(src_port)
            self.memory_twotup[key].set_dst_ports.add(dst_port)
            add_to_counter(self.memory_twotup[key].pkt_protocol_counter, 
                           protocol)
            self.memory_twotup[key].tot_packet_len += length
            self.memory_twotup[key].tot_packet_len += hdr_legth
            self.memory_twotup[key].pkt_flag_counter['ACK'] += ack
            self.memory_twotup[key].pkt_flag_counter['CWR'] += cwr
            self.memory_twotup[key].pkt_flag_counter['ECN'] += ecn
            self.memory_twotup[key].pkt_flag_counter['FIN'] += fin
            self.memory_twotup[key].pkt_flag_counter['RES'] += res
            self.memory_twotup[key].pkt_flag_counter['SYN'] += syn
            self.memory_twotup[key].pkt_flag_counter['URG'] += urg
            self.memory_twotup[key].pkt_flag_counter['PSH'] += psh
            
    def generate_features(self,
                          flow: Tuple[LayerFieldsContainer,
                                      LayerFieldsContainer]):
        """TODO
        """
        pass
