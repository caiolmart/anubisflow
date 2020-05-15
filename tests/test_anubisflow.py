import pytest
from datetime import datetime
import os
import pathlib
import pyshark
import numpy as np

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
    # SYN flag
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
    # SYN flag
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


def test__update_twotuplebi_noupdate():
    afg = AnubisFG()
    capture = pyshark.FileCapture('tests/data/test_100_rows.pcap')
    # First packet is a STP packet that should not be read.
    packet = capture[0]

    afg._update_twotuplebi(packet)
    assert afg.memory_twotup == dict()
    with pytest.raises(AttributeError, match='Attribute ip not in packet'):
        afg._update_twotuplebi(packet, ignore_errors=False)


def test__update_twotuplebi_update():
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
    fwd_pkt_flag_counter = [0] * 8
    # SYN flag
    fwd_pkt_flag_counter[1] = 1
    bck_pkt_flag_counter = [0] * 8

    # Creating
    afg._update_twotuplebi(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'fwd_set_src_ports': {src_port},
                'fwd_set_dst_ports': {dst_port},
                'fwd_pkt_flag_counter': fwd_pkt_flag_counter,
                'fwd_pkt_protocol_counter': {protocol: 1},
                'fwd_tot_header_len': 0,
                'fwd_tot_packet_len': length,
                'bck_set_src_ports': set(),
                'bck_set_dst_ports': set(),
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_pkt_protocol_counter': dict(),
                'bck_tot_header_len': 0,
                'bck_tot_packet_len': 0}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected

    # Updating Forward
    # Third package is another SYN TCP packet with same IPs and Ports
    packet = capture[2]
    new_timestamp = datetime(2018, 12, 1, 11, 17, 11, 183813)
    # SYN flag
    fwd_pkt_flag_counter[1] += 1
    afg._update_twotuplebi(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'fwd_set_src_ports': {src_port},
                'fwd_set_dst_ports': {dst_port},
                'fwd_pkt_flag_counter': fwd_pkt_flag_counter,
                'fwd_pkt_protocol_counter': {protocol: 2},
                'fwd_tot_header_len': 0,
                'fwd_tot_packet_len': length * 2,
                'bck_set_src_ports': set(),
                'bck_set_dst_ports': set(),
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_pkt_protocol_counter': dict(),
                'bck_tot_header_len': 0,
                'bck_tot_packet_len': 0}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected

    # Fourth package is a SYN ACK response TCP packet with inverted IPs and
    # Ports
    packet = capture[3]
    new_timestamp = datetime(2018, 12, 1, 11, 17, 11, 183932)
    # SYN flag
    bck_pkt_flag_counter[1] += 1
    # ACK flag
    bck_pkt_flag_counter[4] += 1
    afg._update_twotuplebi(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'fwd_set_src_ports': {src_port},
                'fwd_set_dst_ports': {dst_port},
                'fwd_pkt_flag_counter': fwd_pkt_flag_counter,
                'fwd_pkt_protocol_counter': {protocol: 2},
                'fwd_tot_header_len': 0,
                'fwd_tot_packet_len': length * 2,
                'bck_set_src_ports': {dst_port},
                'bck_set_dst_ports': {src_port},
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_pkt_protocol_counter': {protocol: 1},
                'bck_tot_header_len': 0,
                'bck_tot_packet_len': length}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected


def test__generate_features_twotupleuni():
    '''
        Feature list:
            qt_pkt
            qt_pkt_tcp
            qt_pkt_udp
            qt_pkt_icmp
            qt_pkt_ip
            qt_prtcl
            qt_src_prt
            qt_dst_prt
            qt_fin_fl
            qt_syn_fl
            qt_psh_fl
            qt_ack_fl
            qt_urg_fl
            qt_rst_fl
            qt_ece_fl
            qt_cwr_fl
            avg_hdr_len
            avg_pkt_len
            frq_pkt
            tm_dur
    '''
    n_features = 20
    ip_src = LayerFieldsContainer('172.16.0.5')
    ip_dst = LayerFieldsContainer('192.168.50.1')
    key = (ip_src, ip_dst)
    afg = AnubisFG()

    # Tuple that is not on the memory.
    empty = afg._generate_features_twotupleuni(key)
    assert empty == [0] * n_features

    # Duration 0
    capture = pyshark.FileCapture('tests/data/test_100_rows.pcap')
    # Second packet is a SYN TCP packet.
    packet = capture[1]
    timestamp = datetime(2018, 12, 1, 11, 17, 11, 183810)
    afg._update_twotupleuni(packet)
    expected = [
        1,  # qt_pkt
        1,  # qt_pkt_tcp
        0,  # qt_pkt_udp
        0,  # qt_pkt_icmp
        0,  # qt_pkt_ip
        1,  # qt_prtcl
        1,  # qt_src_prt
        1,  # qt_dst_prt
        0,  # qt_fin_fl
        1,  # qt_syn_fl
        0,  # qt_psh_fl
        0,  # qt_ack_fl
        0,  # qt_urg_fl
        0,  # qt_rst_fl
        0,  # qt_ece_fl
        0,  # qt_cwr_fl
        0,  # avg_hdr_len
        74,  # avg_pkt_len
        1,  # frq_pkt
        0,  # tm_dur
    ]
    ftrs = afg._generate_features_twotupleuni(key)
    assert ftrs == expected

    # Duration > 0
    # Updating
    # Third package is another SYN TCP packet with same IPs and Ports
    packet = capture[2]
    afg._update_twotupleuni(packet)
    new_timestamp = datetime(2018, 12, 1, 11, 17, 11, 183813)
    dur = (new_timestamp - timestamp).total_seconds()
    expected = [
        2,  # qt_pkt
        2,  # qt_pkt_tcp
        0,  # qt_pkt_udp
        0,  # qt_pkt_icmp
        0,  # qt_pkt_ip
        1,  # qt_prtcl
        1,  # qt_src_prt
        1,  # qt_dst_prt
        0,  # qt_fin_fl
        2,  # qt_syn_fl
        0,  # qt_psh_fl
        0,  # qt_ack_fl
        0,  # qt_urg_fl
        0,  # qt_rst_fl
        0,  # qt_ece_fl
        0,  # qt_cwr_fl
        0,  # avg_hdr_len
        74,  # avg_pkt_len
        2 / dur,  # frq_pkt
        dur,  # tm_dur
    ]
    ftrs = afg._generate_features_twotupleuni(key)
    assert ftrs == expected

    # Using now datetime.
    new_timestamp = datetime.now()
    dur = (new_timestamp - timestamp).total_seconds()
    expected = [
        2,  # qt_pkt
        2,  # qt_pkt_tcp
        0,  # qt_pkt_udp
        0,  # qt_pkt_icmp
        0,  # qt_pkt_ip
        1,  # qt_prtcl
        1,  # qt_src_prt
        1,  # qt_dst_prt
        0,  # qt_fin_fl
        2,  # qt_syn_fl
        0,  # qt_psh_fl
        0,  # qt_ack_fl
        0,  # qt_urg_fl
        0,  # qt_rst_fl
        0,  # qt_ece_fl
        0,  # qt_cwr_fl
        0,  # avg_hdr_len
        74,  # avg_pkt_len
        2 / dur,  # frq_pkt
        dur,  # tm_dur
    ]
    ftrs = afg._generate_features_twotupleuni(key, now=True)
    assert np.isclose(ftrs, expected).all()
