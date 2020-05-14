import pytest
from datetime import datetime
import os, pathlib

from pyshark.packet.fields import LayerFieldsContainer
import src.anubisflow as af

def test_tuple2_default():
    t2 = af.Tuple2Node()
    assert 0 <= (datetime.now() - t2.fst_timestamp).seconds < 5
    assert t2.set_src_ports == set()
    assert t2.set_dst_ports == set()
    assert t2.pkt_flag_counter == dict()
    assert t2.pkt_protocol_counter == dict()
    assert t2.tot_header_len == 0
    assert t2.tot_packet_len == 0

def test_tuple2_ud():
    k = {'fst_timestamp' : datetime(1995, 12, 2), 
         'set_src_ports' : {82, 8888, 42}, 
         'set_dst_ports' : {82, 8888, 42},
         'pkt_flag_counter' : {2 : 5, 4 : 1},
         'pkt_protocol_counter' : {2 : 5, 4 : 1},
         'tot_header_len' : 1048,
         'tot_packet_len' : int(1e10)}
    t2 = af.Tuple2Node(**k)
    assert t2.__dict__ == k

def test_tuple2_raises():
    k = {'fst_timestamp' : 5, 
         'set_src_ports' : datetime(1995, 12, 2), 
         'set_dst_ports' : datetime(1995, 12, 2),
         'pkt_flag_counter' : datetime(1995, 12, 2),
         'pkt_protocol_counter' : datetime(1995, 12, 2),
         'tot_header_len' : datetime(1995, 12, 2),
         'tot_packet_len' : datetime(1995, 12, 2)}
    for item in k.items():
        with pytest.raises(AssertionError):
            _ = af.Tuple2Node(**{item[0] : item[1]})
        with pytest.raises(TypeError):
            _ = af.Tuple2Node(**{'foo' : 'bar'})

def test_anubisfg_default():
    afg = af.AnubisFG()
    assert afg.memory == dict()

def test_anubisfg_ud():
    t2_1 = af.Tuple2Node()
    ip_src_1 = LayerFieldsContainer('192.168.0.1')
    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
    t2_2 = af.Tuple2Node()
    ip_src_2 = LayerFieldsContainer('192.168.0.1')
    ip_dst_2 = LayerFieldsContainer('192.168.0.2')
    memory_1 = {(ip_src_1, ip_dst_1) : t2_1}
    memory_2 = {(ip_src_1, ip_dst_1) : t2_1,
                (ip_src_2, ip_dst_2) : t2_2}

    afg_1 = af.AnubisFG(memory=memory_1)
    afg_2 = af.AnubisFG(memory=memory_2)

    assert memory_1 == afg_1.memory
    assert memory_2 == afg_2.memory
    
def test_anubisfg_raises():
    t2_1 = af.Tuple2Node()
    ip_src_1 = LayerFieldsContainer('192.168.0.1')
    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
    t2_2 = dict()
    ip_src_2 = '192.168.0.1'
    ip_dst_2 = '192.168.0.1'

    memories = [[[ip_src_1, ip_dst_1], t2_1],
                {ip_src_1 : t2_1},
                {(ip_src_2, ip_dst_1) : t2_1},
                {(ip_src_1, ip_dst_2) : t2_1},
                {(ip_src_1, ip_dst_1) : t2_2}]

    for memory in memories:
        with pytest.raises(AssertionError):
            _ = af.AnubisFG(memory=memory)