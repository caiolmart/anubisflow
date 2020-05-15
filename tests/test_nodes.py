import pytest
from datetime import datetime
import os
import pathlib

from pyshark.packet.fields import LayerFieldsContainer
from src.anubisflow import AnubisFG
from src.nodes import TwoTupleUnidirectionalNode, TwoTupleBidirectionalNode


def test_twotupleuni_default():
    t2 = TwoTupleUnidirectionalNode()
    assert 0 <= (datetime.now() - t2.fst_timestamp).seconds < 5
    assert 0 <= (datetime.now() - t2.lst_timestamp).seconds < 5
    assert t2.set_src_ports == set()
    assert t2.set_dst_ports == set()
    assert t2.pkt_flag_counter == [0] * 8
    assert t2.pkt_protocol_counter == dict()
    assert t2.tot_header_len == 0
    assert t2.tot_packet_len == 0


def test_twotupleuni_ud():
    k = {'fst_timestamp': datetime(1995, 12, 2),
         'lst_timestamp': datetime(1995, 12, 2),
         'set_src_ports': {82, 8888, 42},
         'set_dst_ports': {82, 8888, 42},
         'pkt_flag_counter': [10] * 8,
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
    with pytest.raises(AssertionError):
        _ = TwoTupleUnidirectionalNode(pkt_flag_counter=[2] * 6)


def test_twotuplebi_default():
    t2 = TwoTupleBidirectionalNode()
    assert 0 <= (datetime.now() - t2.fst_timestamp).seconds < 5
    assert 0 <= (datetime.now() - t2.lst_timestamp).seconds < 5
    assert t2.fwd_set_src_ports == set()
    assert t2.fwd_set_dst_ports == set()
    assert t2.fwd_pkt_flag_counter == [0] * 8
    assert t2.fwd_pkt_protocol_counter == dict()
    assert t2.fwd_tot_header_len == 0
    assert t2.fwd_tot_packet_len == 0
    assert t2.bck_set_src_ports == set()
    assert t2.bck_set_dst_ports == set()
    assert t2.bck_pkt_flag_counter == [0] * 8
    assert t2.bck_pkt_protocol_counter == dict()
    assert t2.bck_tot_header_len == 0
    assert t2.bck_tot_packet_len == 0


def test_twotuplebi_ud():
    k = {'fst_timestamp': datetime(1995, 12, 2),
         'lst_timestamp': datetime(1995, 12, 2),
         'fwd_set_src_ports': {82, 8888, 42},
         'fwd_set_dst_ports': {82, 8888, 42},
         'fwd_pkt_flag_counter': [10] * 8,
         'fwd_pkt_protocol_counter': {2: 5, 4: 1},
         'fwd_tot_header_len': 1048,
         'fwd_tot_packet_len': int(1e10),
         'bck_set_src_ports': {82, 8888, 42},
         'bck_set_dst_ports': {82, 8888, 42},
         'bck_pkt_flag_counter': [10] * 8,
         'bck_pkt_protocol_counter': {2: 5, 4: 1},
         'bck_tot_header_len': 1048,
         'bck_tot_packet_len': int(1e10), }
    t2 = TwoTupleBidirectionalNode(**k)
    assert t2.__dict__ == k


def test_twotuplebi_raises():
    k = {'fst_timestamp': 42,
         'lst_timestamp': 42,
         'fwd_set_src_ports': datetime(1995, 12, 2),
         'fwd_set_dst_ports': datetime(1995, 12, 2),
         'fwd_pkt_flag_counter': datetime(1995, 12, 2),
         'fwd_pkt_protocol_counter': datetime(1995, 12, 2),
         'fwd_tot_header_len': datetime(1995, 12, 2),
         'fwd_tot_packet_len': datetime(1995, 12, 2),
         'bck_set_src_ports': datetime(1995, 12, 2),
         'bck_set_dst_ports': datetime(1995, 12, 2),
         'bck_pkt_flag_counter': datetime(1995, 12, 2),
         'bck_pkt_protocol_counter': datetime(1995, 12, 2),
         'bck_tot_header_len': datetime(1995, 12, 2),
         'bck_tot_packet_len': datetime(1995, 12, 2)}
    for item in k.items():
        with pytest.raises(AssertionError):
            _ = TwoTupleBidirectionalNode(**{item[0]: item[1]})
    with pytest.raises(AssertionError):
        _ = TwoTupleBidirectionalNode(**{'foo': 'bar'})
    with pytest.raises(AssertionError):
        _ = TwoTupleBidirectionalNode(fwd_pkt_flag_counter=[2] * 6)
    with pytest.raises(AssertionError):
        _ = TwoTupleBidirectionalNode(bck_pkt_flag_counter=[2] * 6)
