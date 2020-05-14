import pytest
from datetime import datetime
import os
import pathlib

from pyshark.packet.fields import LayerFieldsContainer
from src.anubisflow import AnubisFG
from src.nodes import TwoTupleUnidirectionalNode


def test_twotupleuni_default():
    t2 = TwoTupleUnidirectionalNode()
    assert 0 <= (datetime.now() - t2.fst_timestamp).seconds < 5
    assert t2.set_src_ports == set()
    assert t2.set_dst_ports == set()
    assert t2.pkt_flag_counter == dict()
    assert t2.pkt_protocol_counter == dict()
    assert t2.tot_header_len == 0
    assert t2.tot_packet_len == 0


def test_twotupleuni_ud():
    k = {'fst_timestamp': datetime(1995, 12, 2),
         'lst_timestamp': datetime(1995, 12, 2),
         'set_src_ports': {82, 8888, 42},
         'set_dst_ports': {82, 8888, 42},
         'pkt_flag_counter': {2: 5, 4: 1},
         'pkt_protocol_counter': {2: 5, 4: 1},
         'tot_header_len': 1048,
         'tot_packet_len': int(1e10)}
    t2 = TwoTupleUnidirectionalNode(**k)
    assert t2.__dict__ == k


def test_twotupleuni_raises():
    k = {'fst_timestamp': 42,
         'lst_timestamp': 42,
         'set_src_ports': datetime(1995, 12, 2),
         'set_dst_ports': datetime(1995, 12, 2),
         'pkt_flag_counter': datetime(1995, 12, 2),
         'pkt_protocol_counter': datetime(1995, 12, 2),
         'tot_header_len': datetime(1995, 12, 2),
         'tot_packet_len': datetime(1995, 12, 2)}
    for item in k.items():
        with pytest.raises(AssertionError):
            _ = TwoTupleUnidirectionalNode(**{item[0]: item[1]})
    with pytest.raises(AssertionError):
        _ = TwoTupleUnidirectionalNode(**{'foo': 'bar'})


def test_anubisfg_default():
    afg = AnubisFG()
    assert afg.memory_twotup == dict()


def test_anubisfg_ud():
    t2_1 = TwoTupleUnidirectionalNode()
    ip_src_1 = LayerFieldsContainer('192.168.0.1')
    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
    t2_2 = TwoTupleUnidirectionalNode()
    ip_src_2 = LayerFieldsContainer('192.168.0.1')
    ip_dst_2 = LayerFieldsContainer('192.168.0.2')
    memory_twotup_1 = {(ip_src_1, ip_dst_1): t2_1}
    memory_twotup_2 = {(ip_src_1, ip_dst_1): t2_1,
                (ip_src_2, ip_dst_2): t2_2}

    afg_1 = AnubisFG(memory_twotup=memory_twotup_1)
    afg_2 = AnubisFG(memory_twotup=memory_twotup_2)

    assert memory_twotup_1 == afg_1.memory_twotup
    assert memory_twotup_2 == afg_2.memory_twotup


def test_anubisfg_raises():
    t2_1 = TwoTupleUnidirectionalNode()
    ip_src_1 = LayerFieldsContainer('192.168.0.1')
    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
    t2_2 = dict()
    ip_src_2 = '192.168.0.1'
    ip_dst_2 = '192.168.0.1'

    memories = [[[ip_src_1, ip_dst_1], t2_1],
                {ip_src_1: t2_1},
                {(ip_src_2, ip_dst_1): t2_1},
                {(ip_src_1, ip_dst_2): t2_1},
                {(ip_src_1, ip_dst_1): t2_2}]

    for memory_twotup in memories:
        with pytest.raises(AssertionError):
            _ = AnubisFG(memory_twotup=memory_twotup)
