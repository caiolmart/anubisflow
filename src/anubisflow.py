from typing import Tuple, Dict
from datetime import datetime

from pyshark.packet.fields import LayerFieldsContainer
from pyshark.packet.packet import Packet


class TwoTupleNode:
    '''
    Class stores information of a flux.
    It is used internally by AnubisFG.

    Attributes
    ----------
    fst_timestamp: `datetime`
        Timestamp of the first packet of the flux.
    set_src_ports: `set`
        A set of all source ports of packets of the flux.
    set_dst_ports: `set`
        A set of all destination ports of packets of the flux.
    pkt_flag_counter: `dict`
        A counter of the number of flags on packets.
    pkt_protocol_counter: `dict`
        A counter of the number of protocols of packets.
    tot_header_len: `int`
        The sum of all the header lengths of packets of the flux.
    tot_packet_len: `int`
        The sum of all the packet lengths of packets of the flux.
    '''

    def __init__(self, **kwargs):
        self.fst_timestamp = datetime.now()
        self.set_src_ports = set()
        self.set_dst_ports = set()
        self.pkt_flag_counter = dict()
        self.pkt_protocol_counter = dict()
        self.tot_header_len = 0
        self.tot_packet_len = 0

        for key, value in kwargs.items():
            msg1 = f'AssertionError: {key} is invalid argument'
            assert key in self.__dict__, msg1
            msg2 = f'AssertionError: {key} must be type {{type}}'
            _type = type(self.__dict__[key])
            assert isinstance(value, _type), msg2.format(type=_type)
            self.__dict__[key] = value


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
        pyshark.packet.fields.LayerFieldsContainer's, and value TwoTupleNode
        object.

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
                                     TwoTupleNode] = None):
        if memory_twotup is None:
            self.memory_twotup = dict()
        else:
            msg = 'AssertionError: memory_twotup must be of type Dict[Tuple[LayerFieldsContainer, LayerFieldsContainer], TwoTupleNode]'
            assert isinstance(memory_twotup, dict), msg
            for item in memory_twotup.items():
                assert isinstance(item[0], tuple), msg
                assert isinstance(item[0][0], LayerFieldsContainer), msg
                assert isinstance(item[0][1], LayerFieldsContainer), msg
                assert isinstance(item[1], TwoTupleNode), msg
            self.memory_twotup = memory_twotup

    def update(self, packet: Packet):
        """TODO
        Usage
        -----
        capture = pyshark.FileCapture('tests/test_100_rows.pcap')
        for packet in capture:
            update(packet)
        """
        pass

    def generate_features(self,
                          flow: Tuple[LayerFieldsContainer,
                                      LayerFieldsContainer]):
        """TODO
        """
        pass
