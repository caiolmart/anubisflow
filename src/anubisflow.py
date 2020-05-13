from typing import Tuple, Dict
from datetime import datetime

from pyshark.packet.fields import LayerFieldsContainer
from pyshark.packet.packet import Packet

class Tuple2Node:

    def __init__(self, **kwargs):
        self.fst_timestamp = datetime.now()
        self.set_src_ports = set()
        self.set_dst_ports = set()
        self.pkt_flag_counter = dict()
        self.pkt_protocol_counter = dict()
        self.tot_header_len = 0
        self.tot_packet_len = 0

        for key, value in kwargs.items():
            try:
                msg = f'AssertionError: {key} must be type {{type}}'
                if key in self.__dict__:
                    _type = type(self.__dict__[key])
                    assert isinstance(value, _type), msg.format(type=_type)
                    self.__dict__[key] = value
                else:
                    msg = f'TypeError: {key} is invalid argument'
                    raise TypeError(msg)
            except AssertionError as msg:
                raise

class AnubisFG:

    def __init__(self, 
                 memory: Dict[Tuple[LayerFieldsContainer, LayerFieldsContainer], 
                              Tuple2Node] = None):
        if memory == None:
            self.memory = dict()
        else:
            msg = 'AssertionError: memory must be of type Dict[Tuple[LayerFieldsContainer, LayerFieldsContainer], Tuple2Node]'
            try:
                assert isinstance(memory, dict), msg
                for item in memory.items():
                    assert isinstance(item[0], tuple), msg
                    assert isinstance(item[0][0], LayerFieldsContainer), msg
                    assert isinstance(item[0][1], LayerFieldsContainer), msg
                    assert isinstance(item[1], Tuple2Node), msg
            except AssertionError as msg:
                raise
            self.memory = memory

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
                          flow: Tuple[LayerFieldsContainer, LayerFieldsContainer]):
        """TODO
        """
        pass