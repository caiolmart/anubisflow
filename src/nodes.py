from datetime import datetime


class TwoTupleUnidirectionalNode:
    '''
    Class stores information of a unidirectional flux.
    It is used internally by AnubisFG.

    Attributes
    ----------
    fst_timestamp: `datetime`
        Timestamp of the first packet of the flux.
    lst_timestamp: `datetime`
        Timestamp of the last packet of the flux.
    set_src_ports: `set`
        A set of all source ports of packets of the flux.
    set_dst_ports: `set`
        A set of all destination ports of packets of the flux.
    pkt_flag_counter: `list`
        A counter of the number of flags on packets.
        Position of flags in list:
            FIN : 0
            SYN : 1
            RES : 2
            PSH : 3
            ACK : 4
            URG : 5
            ECN : 6
            CWR : 7
    pkt_protocol_counter: `dict`
        A counter of the number of protocols of packets.
    tot_header_len: `int`
        The sum of all the header lengths of packets of the flux.
    tot_packet_len: `int`
        The sum of all the packet lengths of packets of the flux.
    '''

    def __init__(self, **kwargs):
        self.fst_timestamp = datetime.now()
        self.lst_timestamp = self.fst_timestamp
        self.set_src_ports = set()
        self.set_dst_ports = set()
        self.pkt_flag_counter = [0] * 8
        self.pkt_protocol_counter = dict()
        self.tot_header_len = 0
        self.tot_packet_len = 0

        for key, value in kwargs.items():
            msg1 = f'AssertionError: {key} is invalid argument'
            assert key in self.__dict__, msg1
            msg2 = f'AssertionError: {key} must be type {{type}}'
            _type = type(self.__dict__[key])
            assert isinstance(value, _type), msg2.format(type=_type)
            if key == 'pkt_flag_counter':
                msg3 = 'AssertionError: pkt_flag_counter must be an 8 int list'
                assert len(value) == 8, msg3
                for c in value:
                    assert isinstance(c, int), msg3
            self.__dict__[key] = value


class TwoTupleBidirectionalNode:
    '''
    Class stores information of a flux.
    It is used internally by AnubisFG.

    Attributes
    ----------
    fwd_fst_timestamp: `datetime`
        Timestamp of the first forward packet of the flux.
    fwd_lst_timestamp: `datetime`
        Timestamp of the last forward packet of the flux.
    fwd_set_src_ports: `set`
        A set of all source ports of forward packets of the flux.
    fwd_set_dst_ports: `set`
        A set of all destination ports of forward packets of the flux.
    fwd_pkt_flag_counter: `dict`
        A counter of the number of flags on forward packets.
    fwd_pkt_protocol_counter: `dict`
        A counter of the number of protocols of forward packets.
    fwd_tot_header_len: `int`
        The sum of all the header lengths of forward packets of the flux.
    fwd_tot_packet_len: `int`
        The sum of all the packet lengths of forward packets of the flux.
    bck_fst_timestamp: `datetime`
        Timestamp of the first backward packet of the flux.
    bck_lst_timestamp: `datetime`
        Timestamp of the last backward packet of the flux.
    bck_set_src_ports: `set`
        A set of all source ports of backward packets of the flux.
    bck_set_dst_ports: `set`
        A set of all destination ports of backward packets of the flux.
    bck_pkt_flag_counter: `dict`
        A counter of the number of flags on backward packets.
    bck_pkt_protocol_counter: `dict`
        A counter of the number of protocols of backward packets.
    bck_tot_header_len: `int`
        The sum of all the header lengths of backward packets of the flux.
    bck_tot_packet_len: `int`
        The sum of all the packet lengths of backward packets of the flux.
    '''

    def __init__(self, **kwargs):
        self.fwd_fst_timestamp = datetime.now()
        self.fwd_lst_timestamp = self.fwd_fst_timestamp
        self.fwd_set_src_ports = set()
        self.fwd_set_dst_ports = set()
        self.fwd_pkt_flag_counter = [0] * 8
        self.fwd_pkt_protocol_counter = dict()
        self.fwd_tot_header_len = 0
        self.fwd_tot_packet_len = 0
        self.bck_fst_timestamp = datetime.now()
        self.bck_lst_timestamp = self.bck_fst_timestamp
        self.bck_set_src_ports = set()
        self.bck_set_dst_ports = set()
        self.bck_pkt_flag_counter = [0] * 8
        self.bck_pkt_protocol_counter = dict()
        self.bck_tot_header_len = 0
        self.bck_tot_packet_len = 0

        for key, value in kwargs.items():
            msg1 = f'AssertionError: {key} is invalid argument'
            assert key in self.__dict__, msg1
            msg2 = f'AssertionError: {key} must be type {{type}}'
            _type = type(self.__dict__[key])
            assert isinstance(value, _type), msg2.format(type=_type)
            self.__dict__[key] = value
