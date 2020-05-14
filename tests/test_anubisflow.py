import pytest
from datetime import datetime
import os
import pathlib
import pyshark

from pyshark.packet.fields import LayerFieldsContainer
from src.anubisflow import AnubisFG, add_to_counter
from src.nodes import TwoTupleUnidirectionalNode


def test_add_to_counter():
    counter = {1: 3}
    add_to_counter(counter, 1)
    assert counter[1] == 4
    add_to_counter(counter, 2)
    assert counter[2] == 1


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


def test__update_twotupleuni_noupdate():
    afg = AnubisFG()
    capture = pyshark.FileCapture('tests/data/test_100_rows.pcap')
    # First packet is a STP packet that should not be read.
    packet = capture[0]

    afg._update_twotupleuni(packet)
    assert afg.memory_twotup == dict()
    with pytest.raises(AttributeError, match='Attribute ip not in packet'):
        afg._update_twotupleuni(packet, ignore_errors=False)


def test__update_twotupleuni_update():
    afg = AnubisFG()
    capture = pyshark.FileCapture('tests/data/test_100_rows.pcap')
    # Second packet is a SYN TCP packet.
    packet = capture[1]

    ip_src = LayerFieldsContainer('172.16.0.5')
    ip_dst = LayerFieldsContainer('192.168.50.1')
    timestamp = datetime(2018, 12, 1, 11, 17, 11, 183810)
    src_port = 60675
    dst_port = 80
    protocol = 'TCP'
    length = 74
    pkt_flag_counter = [0] * 8
    pkt_flag_counter[1] = 1

    # Creating
    afg._update_twotupleuni(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'set_src_ports': {src_port},
                'set_dst_ports': {dst_port},
                'pkt_flag_counter': pkt_flag_counter,
                'pkt_protocol_counter': {protocol: 1},
                'tot_header_len': 0,
                'tot_packet_len': length}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected

    # Updating
    # Third package is another SYN TCP packet with same IPs and Ports
    packet = capture[2]
    new_timestamp = datetime(2018, 12, 1, 11, 17, 11, 183813)
    pkt_flag_counter[1] += 1
    afg._update_twotupleuni(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'set_src_ports': {src_port},
                'set_dst_ports': {dst_port},
                'pkt_flag_counter': pkt_flag_counter,
                'pkt_protocol_counter': {protocol: 2},
                'tot_header_len': 0,
                'tot_packet_len': length * 2}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected
