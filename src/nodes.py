from datetime import datetime


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

