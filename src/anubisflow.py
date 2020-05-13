from typing import Tuple, Dict
from datetime import datetime

from pyshark.packet.fields import LayerFieldsContainer


class AnubisFG:

    def __init__(self, 
                 memory: Dict[Tuple[LayerFieldsContainer, LayerFieldsContainer], 
                              Tuple2Node] = None):
        if memory == None:
            memory = dict()
        else:
            assert type(memory) == dict
            for item in memory.items():
                assert type(item[0]) == tuple
                assert type(item[0][0]) == LayerFieldsContainer
                assert type(item[0][1]) == LayerFieldsContainer
                assert type(item[1]) == Tuple2Node
            self.memory = memory

class Tuple2Node:

    def __init__(self, **kwargs):
        self.fst_timestamp = datetime.now()
        self.set_src_ports = set()
        self.set_dst_ports = set()
        self.pkt_flag_counter = dict()
        self.pkt_protocol_counter = dict()
        self.tot_header_len = 0
        self.tot_packet_len = 0
