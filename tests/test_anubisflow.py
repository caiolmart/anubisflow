import pytest
from datetime import datetime
import os
import pathlib
import pyshark
import numpy as np

from pyshark.packet.fields import LayerFieldsContainer
from scapy.utils import rdpcap
from scapy.layers.inet import IP, UDP, TCP, ICMP

from anubisflow.anubisflow import AnubisFG, add_to_counter
from anubisflow.nodes import TwoTupleUnidirectionalNode, TwoTupleBidirectionalNode, FiveTupleUnidirectionalNode, FiveTupleBidirectionalNode


def test_add_to_counter():
    counter = {1: 3}
    add_to_counter(counter, 1)
    assert counter[1] == 4
    add_to_counter(counter, 2)
    assert counter[2] == 1


def test_anubisfg_default():
    afg = AnubisFG()
    assert afg.memory_twotup == dict()
    assert afg.memory_fivetup == dict()
    assert afg.lst_timestamp is None


def test_anubisfg_onlytwo():
    afg = AnubisFG(only_twotuple=True)
    assert afg.memory_twotup == dict()
    assert afg.memory_fivetup is None


def test_anubisfg_onlyfive():
    afg = AnubisFG(only_fivetuple=True)
    assert afg.memory_twotup is None
    assert afg.memory_fivetup == dict()


def test_anubisfg_ud():
    t2_1 = TwoTupleBidirectionalNode()
    ip_src_1 = '192.168.0.1'
    ip_dst_1 = '192.168.0.2'
    t2_2 = TwoTupleBidirectionalNode()
    ip_src_2 = '192.168.0.1'
    ip_dst_2 = '192.168.0.2'
    memory_twotup_1 = {(ip_src_1, ip_dst_1): t2_1}
    memory_twotup_2 = {(ip_src_1, ip_dst_1): t2_1,
                       (ip_src_2, ip_dst_2): t2_2}
    afg_1 = AnubisFG(bidirectional=True, memory_twotup=memory_twotup_1)
    afg_2 = AnubisFG(bidirectional=True, memory_twotup=memory_twotup_2)
    assert memory_twotup_1 == afg_1.memory_twotup
    assert memory_twotup_2 == afg_2.memory_twotup

    t5_1 = FiveTupleBidirectionalNode()
    ip_src_1 = '192.168.0.1'
    ip_dst_1 = '192.168.0.2'
    src_port_1 = 80
    dst_port_1 = 80
    protocol_1 = 6
    protocol_2 = 17
    memory_fivetup_1 = {(ip_src_1, src_port_1, ip_dst_1, dst_port_1,
                         protocol_1): t5_1}
    memory_fivetup_2 = {(ip_src_1, src_port_1, ip_dst_1, dst_port_1,
                         protocol_1): t5_1,
                        (ip_src_1, src_port_1, ip_dst_1, dst_port_1,
                         protocol_2): t5_1}
    afg_1 = AnubisFG(bidirectional=True, memory_fivetup=memory_fivetup_1)
    afg_2 = AnubisFG(bidirectional=True, memory_fivetup=memory_fivetup_2)
    assert memory_fivetup_1 == afg_1.memory_fivetup
    assert memory_fivetup_2 == afg_2.memory_fivetup


def test_anubisfg_raises():
    t2_1 = TwoTupleBidirectionalNode()
    ip_src_1 = '192.168.0.1'
    ip_dst_1 = '192.168.0.2'
    t2_2 = dict()
    ip_src_2 = 19216801
    ip_dst_2 = 19216801

    memories = [[[ip_src_1, ip_dst_1], t2_1],
                {ip_src_1: t2_1},
                {(ip_src_2, ip_dst_1): t2_1},
                {(ip_src_1, ip_dst_2): t2_1},
                {(ip_src_1, ip_dst_1): t2_2}]

    for memory_twotup in memories:
        with pytest.raises(AssertionError):
            _ = AnubisFG(bidirectional=True, memory_twotup=memory_twotup)

    t5_1 = FiveTupleBidirectionalNode()
    src_port_1 = 80
    dst_port_1 = 80
    protocol_1 = 6
    src_port_2 = '80'
    dst_port_2 = '80'
    protocol_2 = 'TCP'
    t5_2 = dict()

    memories = [[[ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_1], t5_1],
                {ip_src_1: t5_1},
                {(ip_src_2, src_port_1, ip_dst_1, dst_port_1, protocol_1): t5_1},
                {(ip_src_1, src_port_2, ip_dst_1, dst_port_1, protocol_1): t5_1},
                {(ip_src_1, src_port_1, ip_dst_2, dst_port_1, protocol_1): t5_1},
                {(ip_src_1, src_port_1, ip_dst_1, dst_port_2, protocol_1): t5_1},
                {(ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_2): t5_1},
                {(ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_1): t5_2}]
    for memory_fivetup in memories:
        with pytest.raises(AssertionError):
            _ = AnubisFG(memory_fivetup=memory_fivetup)

    with pytest.raises(AssertionError):
        _ = AnubisFG(only_twotuple=True, only_fivetuple=True)


def test_anubisfg_uni_raises():
    t2_1 = TwoTupleUnidirectionalNode()
    ip_src_1 = '192.168.0.1'
    ip_dst_1 = '192.168.0.2'
    t2_2 = dict()
    ip_src_2 = 19216801
    ip_dst_2 = 19216801

    memories = [[[ip_src_1, ip_dst_1], t2_1],
                {ip_src_1: t2_1},
                {(ip_src_2, ip_dst_1): t2_1},
                {(ip_src_1, ip_dst_2): t2_1},
                {(ip_src_1, ip_dst_1): t2_2}]

    for memory_twotup in memories:
        with pytest.raises(AssertionError):
            _ = AnubisFG(bidirectional=False, memory_twotup=memory_twotup)

    t5_1 = FiveTupleUnidirectionalNode()
    src_port_1 = 80
    dst_port_1 = 80
    protocol_1 = 6
    src_port_2 = '80'
    dst_port_2 = '80'
    protocol_2 = 'TCP'
    t5_2 = dict()

    memories = [[[ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_1], t5_1],
                {ip_src_1: t5_1},
                {(ip_src_2, src_port_1, ip_dst_1, dst_port_1, protocol_1): t5_1},
                {(ip_src_1, src_port_2, ip_dst_1, dst_port_1, protocol_1): t5_1},
                {(ip_src_1, src_port_1, ip_dst_2, dst_port_1, protocol_1): t5_1},
                {(ip_src_1, src_port_1, ip_dst_1, dst_port_2, protocol_1): t5_1},
                {(ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_2): t5_1},
                {(ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_1): t5_2}]
    for memory_fivetup in memories:
        with pytest.raises(AssertionError):
            _ = AnubisFG(bidirectional=False, memory_fivetup=memory_fivetup)


def test__update_twotupleuni_noupdate():
    afg = AnubisFG(bidirectional=False)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # First packet is a STP packet that should not be read.
    packet = capture[0]

    afg._update_twotupleuni(packet)
    assert afg.memory_twotup == dict()
    with pytest.raises(IndexError, match='Packet does not have an IP layer'):
        afg._update_twotupleuni(packet, ignore_errors=False)


def test__update_twotupleuni_update():
    afg = AnubisFG(bidirectional=False)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # Second packet is a SYN TCP packet.
    packet = capture[1]

    ip_src = '172.16.0.5'
    ip_dst = '192.168.50.1'
    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
    src_port = 60675
    dst_port = 80
    protocol = 6
    hdr_len = 20
    length = 74
    ttl = 63
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
                'tot_header_len': hdr_len,
                'tot_packet_len': length,
                'tot_ttl': ttl}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected

    # Updating
    # Third packet is another SYN TCP packet with same IPs and Ports
    packet = capture[2]
    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
    # SYN flag
    pkt_flag_counter[1] += 1
    afg._update_twotupleuni(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'set_src_ports': {src_port},
                'set_dst_ports': {dst_port},
                'pkt_flag_counter': pkt_flag_counter,
                'pkt_protocol_counter': {protocol: 2},
                'tot_header_len': hdr_len * 2,
                'tot_packet_len': length * 2,
                'tot_ttl': ttl * 2}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected


def test__update_twotuplebi_noupdate():
    afg = AnubisFG(bidirectional=True)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # First packet is a STP packet that should not be read.
    packet = capture[0]

    afg._update_twotuplebi(packet)
    assert afg.memory_twotup == dict()
    with pytest.raises(IndexError, match='Packet does not have an IP layer'):
        afg._update_twotupleuni(packet, ignore_errors=False)
    
    


def test__update_twotuplebi_update():
    afg = AnubisFG(bidirectional=True)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # Second packet is a SYN TCP packet.
    packet = capture[1]

    ip_src = '172.16.0.5'
    ip_dst = '192.168.50.1'
    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
    src_port = 60675
    dst_port = 80
    protocol = 6
    hdr_len = 20
    length = 74
    ttl = 63
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
                'fwd_tot_header_len': hdr_len,
                'fwd_tot_packet_len': length,
                'fwd_tot_ttl': ttl,
                'bck_set_src_ports': set(),
                'bck_set_dst_ports': set(),
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_pkt_protocol_counter': dict(),
                'bck_tot_header_len': 0,
                'bck_tot_packet_len': 0,
                'bck_tot_ttl': 0}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected

    # Updating Forward
    # Third packet is another SYN TCP packet with same IPs and Ports
    packet = capture[2]
    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
    # SYN flag
    fwd_pkt_flag_counter[1] += 1
    afg._update_twotuplebi(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'fwd_set_src_ports': {src_port},
                'fwd_set_dst_ports': {dst_port},
                'fwd_pkt_flag_counter': fwd_pkt_flag_counter,
                'fwd_pkt_protocol_counter': {protocol: 2},
                'fwd_tot_header_len': hdr_len * 2,
                'fwd_tot_packet_len': length * 2,
                'fwd_tot_ttl': ttl * 2,
                'bck_set_src_ports': set(),
                'bck_set_dst_ports': set(),
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_pkt_protocol_counter': dict(),
                'bck_tot_header_len': 0,
                'bck_tot_packet_len': 0,
                'bck_tot_ttl': 0}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected

    # Fourth packet is a SYN ACK response TCP packet with inverted IPs and
    # Ports
    packet = capture[3]
    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183932)
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
                'fwd_tot_header_len': hdr_len * 2,
                'fwd_tot_packet_len': length * 2,
                'fwd_tot_ttl': ttl * 2,
                'bck_set_src_ports': {dst_port},
                'bck_set_dst_ports': {src_port},
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_pkt_protocol_counter': {protocol: 1},
                'bck_tot_header_len': hdr_len,
                'bck_tot_packet_len': length,
                'bck_tot_ttl': 64}
    assert len(afg.memory_twotup) == 1
    assert afg.memory_twotup[(ip_src, ip_dst)].__dict__ == expected


def test__update_fivetupleuni_noupdate():
    afg = AnubisFG(bidirectional=False)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # First packet is a STP packet that should not be read.
    packet = capture[0]

    afg._update_fivetupleuni(packet)
    assert afg.memory_fivetup == dict()
    with pytest.raises(IndexError, match='Packet does not have an IP layer'):
        afg._update_fivetupleuni(packet, ignore_errors=False)
    
    


def test__update_fivetupleuni_update():
    afg = AnubisFG(bidirectional=False)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # Second packet is a SYN TCP packet.
    packet = capture[1]

    ip_src = '172.16.0.5'
    ip_dst = '192.168.50.1'
    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
    src_port = 60675
    dst_port = 80
    protocol = 6
    key = (ip_src, src_port, ip_dst, dst_port, protocol)
    length = 74
    hdr_length = 20
    ttl = 63
    pkt_flag_counter = [0] * 8
    # SYN flag
    pkt_flag_counter[1] = 1

    # Creating
    afg._update_fivetupleuni(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'pkt_flag_counter': pkt_flag_counter,
                'tot_pkt': 1,
                'tot_header_len': hdr_length,
                'tot_packet_len': length,
                'max_pkt_len': length,
                'min_pkt_len': length,
                'tot_ttl': ttl}
    assert len(afg.memory_fivetup) == 1
    assert afg.memory_fivetup[key].__dict__ == expected

    # Updating
    # Third packet is another SYN TCP packet with same IPs and Ports
    packet = capture[2]
    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
    # SYN flag
    pkt_flag_counter[1] += 1
    afg._update_fivetupleuni(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'pkt_flag_counter': pkt_flag_counter,
                'tot_pkt': 2,
                'tot_header_len': hdr_length * 2,
                'tot_packet_len': length * 2,
                'max_pkt_len': length,
                'min_pkt_len': length,
                'tot_ttl': ttl * 2}
    assert len(afg.memory_fivetup) == 1
    assert afg.memory_fivetup[key].__dict__ == expected



def test__update_fivetuplebi_noupdate():
    afg = AnubisFG(bidirectional=True)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # First packet is a STP packet that should not be read.
    packet = capture[0]

    afg._update_fivetuplebi(packet)
    assert afg.memory_fivetup == dict()
    with pytest.raises(IndexError, match='Packet does not have an IP layer'):
        afg._update_fivetuplebi(packet, ignore_errors=False)

    


def test__update_fivetuplebi_update():
    afg = AnubisFG(bidirectional=True)
    capture = rdpcap('tests/data/test_100_rows.pcap')
    # Second packet is a SYN TCP packet.
    packet = capture[1]

    ip_src = '172.16.0.5'
    ip_dst = '192.168.50.1'
    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
    src_port = 60675
    dst_port = 80
    protocol = 6
    key = (ip_src, src_port, ip_dst, dst_port, protocol)
    length = 74
    hdr_len = 20
    ttl = 63
    fwd_pkt_flag_counter = [0] * 8
    # SYN flag
    fwd_pkt_flag_counter[1] = 1
    bck_pkt_flag_counter = [0] * 8

    # Creating
    afg._update_fivetuplebi(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'fwd_pkt_flag_counter': fwd_pkt_flag_counter,
                'fwd_tot_pkt': 1,
                'fwd_tot_header_len': hdr_len,
                'fwd_tot_packet_len': length,
                'fwd_max_pkt_len': length,
                'fwd_min_pkt_len': length,
                'fwd_tot_ttl': ttl,
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_tot_pkt': 0,
                'bck_tot_header_len': 0,
                'bck_tot_packet_len': 0,
                'bck_max_pkt_len': 0,
                'bck_min_pkt_len': 0,
                'bck_tot_ttl': 0}
    assert len(afg.memory_fivetup) == 1
    assert afg.memory_fivetup[key].__dict__ == expected

    # Updating Forward
    # Third packet is another SYN TCP packet with same IPs and Ports
    packet = capture[2]
    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
    # SYN flag
    fwd_pkt_flag_counter[1] += 1
    afg._update_fivetuplebi(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'fwd_pkt_flag_counter': fwd_pkt_flag_counter,
                'fwd_tot_pkt': 2,
                'fwd_tot_header_len': hdr_len * 2,
                'fwd_tot_packet_len': length * 2,
                'fwd_max_pkt_len': length,
                'fwd_min_pkt_len': length,
                'fwd_tot_ttl': ttl * 2,
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_tot_pkt': 0,
                'bck_tot_header_len': 0,
                'bck_tot_packet_len': 0,
                'bck_max_pkt_len': 0,
                'bck_min_pkt_len': 0,
                'bck_tot_ttl': 0}
    assert len(afg.memory_fivetup) == 1
    assert afg.memory_fivetup[key].__dict__ == expected

    # Fourth packet is a SYN ACK response TCP packet with inverted IPs and
    # Ports
    packet = capture[3]
    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183932)
    # SYN flag
    bck_pkt_flag_counter[1] += 1
    # ACK flag
    bck_pkt_flag_counter[4] += 1
    afg._update_fivetuplebi(packet)
    expected = {'fst_timestamp': timestamp,
                'lst_timestamp': new_timestamp,
                'fwd_pkt_flag_counter': fwd_pkt_flag_counter,
                'fwd_tot_pkt': 2,
                'fwd_tot_header_len': hdr_len * 2,
                'fwd_tot_packet_len': length * 2,
                'fwd_max_pkt_len': length,
                'fwd_min_pkt_len': length,
                'fwd_tot_ttl': ttl * 2,
                'bck_pkt_flag_counter': bck_pkt_flag_counter,
                'bck_tot_pkt': 1,
                'bck_tot_header_len': hdr_len,
                'bck_tot_packet_len': length,
                'bck_max_pkt_len': length,
                'bck_min_pkt_len': length,
                'bck_tot_ttl': 64}
    assert len(afg.memory_fivetup) == 1
    assert afg.memory_fivetup[key].__dict__ == expected

    


#def test_update():
#    capture = rdpcap('tests/data/test_100_rows.pcap')
#    # Will be tested considering all possible sets of attributes.
#    for bidir in [True, False]:
#        for onlytwo in [True, False]:
#            for onlyfive in set([not onlytwo, False]):
#                # This will be updated by the method update.
#                afg_1 = AnubisFG(bidirectional=bidir, only_twotuple=onlytwo,
#                                 only_fivetuple=onlyfive)
#                # This will be updated by the specific method(s) tested above.
#                afg_2 = AnubisFG(bidirectional=bidir, only_twotuple=onlytwo,
#                                 only_fivetuple=onlyfive)
#                for i in range(1, 4):
#                    packet = capture[i]
#                    afg_1.update(packet)
#                    assert afg_1.lst_timestamp == packet.sniff_time
#                    if bidir:
#                        if onlytwo:
#                            afg_2._update_twotuplebi(packet)
#                        elif onlyfive:
#                            afg_2._update_fivetuplebi(packet)
#                        else:
#                            afg_2._update_twotuplebi(packet)
#                            afg_2._update_fivetuplebi(packet)
#                    else:
#                        if onlytwo:
#                            afg_2._update_twotupleuni(packet)
#                        elif onlyfive:
#                            afg_2._update_fivetupleuni(packet)
#                        else:
#                            afg_2._update_twotupleuni(packet)
#                            afg_2._update_fivetupleuni(packet)
#
#                    if afg_1.memory_twotup is None:
#                        assert afg_2.memory_twotup is None
#                    else:
#                        assert afg_1.memory_twotup.keys() == afg_2.memory_twotup.keys()
#                        for key in afg_1.memory_twotup.keys():
#                            assert afg_1.memory_twotup[key].__dict__ == afg_2.memory_twotup[key].__dict__
#
#                    if afg_1.memory_fivetup is None:
#                        assert afg_2.memory_fivetup is None
#                    else:
#                        assert afg_1.memory_fivetup.keys() == afg_2.memory_fivetup.keys()
#                        for key in afg_1.memory_fivetup.keys():
#                            assert afg_1.memory_fivetup[key].__dict__ == afg_2.memory_fivetup[key].__dict__
#    
#    
#
#
#def test__generate_features_twotupleuni():
#    '''
#        Feature list:
#            qt_pkt
#            qt_pkt_tcp
#            qt_pkt_udp
#            qt_pkt_icmp
#            qt_pkt_ip
#            qt_prtcl
#            qt_src_prt
#            qt_dst_prt
#            qt_fin_fl
#            qt_syn_fl
#            qt_res_fl
#            qt_psh_fl
#            qt_ack_fl
#            qt_urg_fl
#            qt_ecn_fl
#            qt_cwr_fl
#            avg_hdr_len
#            avg_pkt_len
#            frq_pkt
#            avg_ttl
#            tm_dur_s
#    '''
#    n_features = 21
#    ip_src = '172.16.0.5'
#    ip_dst = '192.168.50.1'
#    key = (ip_src, ip_dst)
#    afg = AnubisFG(bidirectional=False)
#
#    # Tuple that is not on the memory.
#    empty = afg._generate_features_twotupleuni(key)
#    assert empty == [0] * n_features
#
#    # Duration 0
#    capture = rdpcap('tests/data/test_100_rows.pcap')
#    # Second packet is a SYN TCP packet.
#    packet = capture[1]
#    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
#    afg._update_twotupleuni(packet)
#    expected = [
#        1,  # qt_pkt
#        1,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        1,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        1,  # frq_pkt
#        63,  # avg_ttl
#        0,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_twotupleuni(key)
#    assert ftrs == expected
#
#    # Duration > 0
#    # Updating
#    # Third packet is another SYN TCP packet with same IPs and Ports
#    packet = capture[2]
#    afg._update_twotupleuni(packet)
#    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # qt_pkt
#        2,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        2,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        2 / dur,  # frq_pkt
#        63,  # avg_ttl
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_twotupleuni(key)
#    assert ftrs == expected
#
#    # Using now datetime.
#    new_timestamp = datetime.now()
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # qt_pkt
#        2,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        2,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        2 / dur,  # frq_pkt
#        63,  # avg_ttl
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_twotupleuni(key, now=True)
#    assert np.isclose(ftrs, expected).all()
#
#    # Zero forward packets on existing flow
#    ip_src_1 = LayerFieldsContainer('192.168.0.1')
#    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
#    key_1 = (ip_src_1, ip_dst_1)
#    t2_1 = TwoTupleUnidirectionalNode()
#    memory_twotup_1 = {key_1: t2_1}
#    afg_1 = AnubisFG(memory_twotup=memory_twotup_1, bidirectional=False)
#    ftrs = afg_1._generate_features_twotupleuni(key_1)
#    assert ftrs == [0] * n_features
#    
#
#
#def test__generate_features_twotuplebi():
#    '''
#
#    '''
#    n_features = 41
#    ip_src = '172.16.0.5'
#    ip_dst = '192.168.50.1'
#    key = (ip_src, ip_dst)
#    afg = AnubisFG(bidirectional=True)
#
#    # Tuple that is not on the memory.
#    empty = afg._generate_features_twotuplebi(key)
#    assert empty == [0] * n_features
#
#    # Duration 0
#    capture = rdpcap('tests/data/test_100_rows.pcap')
#    # Second packet is a SYN TCP packet.
#    packet = capture[1]
#    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
#
#    afg._update_twotuplebi(packet)
#    expected = [
#        # fwd
#        1,  # qt_pkt
#        1,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        1,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        1,  # frq_pkt
#        63, # avg_ttl
#        # bck
#        0,  # qt_pkt
#        0,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        0,  # qt_prtcl
#        0,  # qt_src_prt
#        0,  # qt_dst_prt
#        0,  # qt_fin_fl
#        0,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        0,  # avg_pkt_len
#        0,  # frq_pkt
#        0,  # avg_ttl
#        # non-directional
#        0,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_twotuplebi(key)
#    assert ftrs == expected
#
#    # Inverted
#    expected = [
#        # bck
#        0,  # qt_pkt
#        0,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        0,  # qt_prtcl
#        0,  # qt_src_prt
#        0,  # qt_dst_prt
#        0,  # qt_fin_fl
#        0,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        0,  # avg_pkt_len
#        0,  # frq_pkt
#        0,  # avg_ttl
#        # fwd
#        1,  # qt_pkt
#        1,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        1,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        1,  # frq_pkt
#        63, # avg_ttl
#        # non-directional
#        0,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_twotuplebi((key[1], key[0]))
#    assert ftrs == expected
#
#    # Duration > 0
#    # Updating
#    # Third packet is another SYN TCP packet with same IPs and Ports
#    packet = capture[2]
#    afg._update_twotuplebi(packet)
#    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # qt_pkt
#        2,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        2,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        2 / dur,  # frq_pkt
#        63,  # avg_ttl
#        # bck
#        0,  # qt_pkt
#        0,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        0,  # qt_prtcl
#        0,  # qt_src_prt
#        0,  # qt_dst_prt
#        0,  # qt_fin_fl
#        0,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        0,  # avg_pkt_len
#        0,  # frq_pkt
#        0,  # avg_ttl
#        # non-directional
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_twotuplebi(key)
#    assert ftrs == expected
#
#    # Using now datetime.
#    new_timestamp = datetime.now()
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # qt_pkt
#        2,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        2,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        2 / dur,  # frq_pkt
#        63,  # avg_ttl
#        # bck
#        0,  # qt_pkt
#        0,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        0,  # qt_prtcl
#        0,  # qt_src_prt
#        0,  # qt_dst_prt
#        0,  # qt_fin_fl
#        0,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        0,  # avg_pkt_len
#        0,  # frq_pkt
#        0,  # avg_ttl
#        # non-directional
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_twotuplebi(key, now=True)
#    assert np.isclose(ftrs, expected).all()
#
#    # Backward features
#    # Updating
#    # Fourth packet is a SYN ACK response TCP packet with inverted IPs and
#    packet = capture[3]
#    afg._update_twotuplebi(packet)
#    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183932)
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # qt_pkt
#        2,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        2,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        2 / dur,  # frq_pkt
#        63,  # avg_ttl
#        # bck
#        1,  # qt_pkt
#        1,  # qt_pkt_tcp
#        0,  # qt_pkt_udp
#        0,  # qt_pkt_icmp
#        0,  # qt_pkt_ip
#        1,  # qt_prtcl
#        1,  # qt_src_prt
#        1,  # qt_dst_prt
#        0,  # qt_fin_fl
#        1,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        1,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        1 / dur,  # frq_pkt
#        64,  # avg_ttl
#        # non-directional
#        dur,  # tm_dur_s
#    ]
#
#    ftrs = afg._generate_features_twotuplebi(key)
#    # breakpoint()
#    assert np.isclose(ftrs, expected).all()
#
#    # Zero forward packets on existing flow
#    ip_src_1 = LayerFieldsContainer('192.168.0.1')
#    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
#    key_1 = (ip_src_1, ip_dst_1)
#    t2_1 = TwoTupleBidirectionalNode()
#    memory_twotup_1 = {key_1: t2_1}
#    afg_1 = AnubisFG(bidirectional=True, memory_twotup=memory_twotup_1)
#    ftrs = afg_1._generate_features_twotuplebi(key_1)
#    assert ftrs == [0] * n_features
#
#    
#
#
#def test__generate_features_fivetupleuni():
#    '''
#        Feature list:
#            qt_pkt
#            qt_fin_fl
#            qt_syn_fl
#            qt_res_fl
#            qt_psh_fl
#            qt_ack_fl
#            qt_urg_fl
#            qt_ecn_fl
#            qt_cwr_fl
#            avg_hdr_len
#            avg_pkt_len
#            max_pkt_len
#            min_pkt_len
#            frq_pkt
#            avg_ttl
#            tm_dur_s
#    '''
#    n_features = 16
#    ip_src = '172.16.0.5'
#    ip_dst = '192.168.50.1'
#    src_port = 60675
#    dst_port = 80
#    protocol = 6
#    key = (ip_src, src_port, ip_dst, dst_port, protocol)
#    afg = AnubisFG(bidirectional=False)
#
#    # Tuple that is not on the memory.
#    empty = afg._generate_features_fivetupleuni(key)
#    assert empty == [0] * n_features
#
#    # Duration 0
#    capture = rdpcap('tests/data/test_100_rows.pcap')
#    # Second packet is a SYN TCP packet.
#    packet = capture[1]
#    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
#    afg._update_fivetupleuni(packet)
#    expected = [
#        1,  # qt_pkt
#        0,  # qt_fin_fl
#        1,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        74,  # max_pkt_len
#        74,  # min_pkt_len
#        1,  # frq_pkt
#        63,  # avg_ttl
#        0,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_fivetupleuni(key)
#    assert ftrs == expected
#
#    # Duration > 0
#    # Updating
#    # Third packet is another SYN TCP packet with same IPs and Ports
#    packet = capture[2]
#    afg._update_fivetupleuni(packet)
#    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # qt_pkt
#        0,  # qt_fin_fl
#        2,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        74,  # max_pkt_len
#        74,  # min_pkt_len
#        2 / dur,  # frq_pkt
#        63,  # avg_ttl
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_fivetupleuni(key)
#    assert ftrs == expected
#
#    # Using now datetime.
#    new_timestamp = datetime.now()
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # qt_pkt
#        0,  # qt_fin_fl
#        2,  # qt_syn_fl
#        0,  # qt_res_fl
#        0,  # qt_psh_fl
#        0,  # qt_ack_fl
#        0,  # qt_urg_fl
#        0,  # qt_ecn_fl
#        0,  # qt_cwr_fl
#        0,  # avg_hdr_len
#        74,  # avg_pkt_len
#        74,  # max_pkt_len
#        74,  # min_pkt_len
#        2 / dur,  # frq_pkt
#        63,  # avg_ttl
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_fivetupleuni(key, now=True)
#    assert np.isclose(ftrs, expected).all()
#
#    # Zero forward packets on existing flow
#    ip_src_1 = LayerFieldsContainer('192.168.0.1')
#    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
#    src_port_1 = '80'
#    dst_port_1 = '80'
#    protocol_1 = 'TCP'
#    key_1 = (ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_1)
#    t5_1 = FiveTupleUnidirectionalNode()
#    memory_fivetup_1 = {key_1: t5_1}
#    afg_1 = AnubisFG(memory_fivetup=memory_fivetup_1, bidirectional=False)
#    ftrs = afg_1._generate_features_fivetupleuni(key_1)
#    assert ftrs == [0] * n_features
#
#    
#
#
#def test__generate_features_fivetuplebi():
#    '''
#        Feature list:
#        Forward
#            fwd_qt_pkt
#            fwd_qt_fin_fl
#            fwd_qt_syn_fl
#            fwd_qt_res_fl
#            fwd_qt_psh_fl
#            fwd_qt_ack_fl
#            fwd_qt_urg_fl
#            fwd_qt_ecn_fl
#            fwd_qt_cwr_fl
#            fwd_avg_hdr_len
#            fwd_avg_pkt_len
#            fwd_max_pkt_len
#            fwd_min_pkt_len
#            fwd_frq_pkt
#            fwd_avg_ttl
#        Backward
#            bck_qt_pkt
#            bck_qt_fin_fl
#            bck_qt_syn_fl
#            bck_qt_res_fl
#            bck_qt_psh_fl
#            bck_qt_ack_fl
#            bck_qt_urg_fl
#            bck_qt_ecn_fl
#            bck_qt_cwr_fl
#            bck_avg_hdr_len
#            bck_avg_pkt_len
#            bck_max_pkt_len
#            bck_min_pkt_len
#            bck_frq_pkt
#            bck_avg_ttl
#        Non-directional
#            tm_dur_s
#    '''
#    n_features = 31
#    ip_src = '172.16.0.5'
#    ip_dst = '192.168.50.1'
#    src_port = 60675
#    dst_port = 80
#    protocol = 6
#    key = (ip_src, src_port, ip_dst, dst_port, protocol)
#    afg = AnubisFG(bidirectional=True)
#
#    # Tuple that is not on the memory.
#    empty = afg._generate_features_fivetuplebi(key)
#    assert empty == [0] * n_features
#
#    # Duration 0
#    capture = rdpcap('tests/data/test_100_rows.pcap')
#    # Second packet is a SYN TCP packet.
#    packet = capture[1]
#    timestamp = datetime(2018, 12, 1, 13, 17, 11, 183810)
#    afg._update_fivetuplebi(packet)
#    expected = [
#        1,  # fwd_qt_pkt
#        0,  # fwd_qt_fin_fl
#        1,  # fwd_qt_syn_fl
#        0,  # fwd_qt_res_fl
#        0,  # fwd_qt_psh_fl
#        0,  # fwd_qt_ack_fl
#        0,  # fwd_qt_urg_fl
#        0,  # fwd_qt_ecn_fl
#        0,  # fwd_qt_cwr_fl
#        0,  # fwd_avg_hdr_len
#        74,  # fwd_avg_pkt_len
#        74,  # fwd_max_pkt_len
#        74,  # fwd_min_pkt_len
#        1,  # fwd_frq_pkt
#        63,  # fwd_avg_ttl
#        0,  # bck_qt_pkt
#        0,  # bck_qt_fin_fl
#        0,  # bck_qt_syn_fl
#        0,  # bck_qt_res_fl
#        0,  # bck_qt_psh_fl
#        0,  # bck_qt_ack_fl
#        0,  # bck_qt_urg_fl
#        0,  # bck_qt_ecn_fl
#        0,  # bck_qt_cwr_fl
#        0,  # bck_avg_hdr_len
#        0,  # bck_avg_pkt_len
#        0,  # bck_max_pkt_len
#        0,  # bck_min_pkt_len
#        0,  # bck_frq_pkt
#        0,  # bck_avg_ttl
#        0,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_fivetuplebi(key)
#    assert ftrs == expected
#
#    # Inverted
#    expected = [
#        0,  # bck_qt_pkt
#        0,  # bck_qt_fin_fl
#        0,  # bck_qt_syn_fl
#        0,  # bck_qt_res_fl
#        0,  # bck_qt_psh_fl
#        0,  # bck_qt_ack_fl
#        0,  # bck_qt_urg_fl
#        0,  # bck_qt_ecn_fl
#        0,  # bck_qt_cwr_fl
#        0,  # bck_avg_hdr_len
#        0,  # bck_avg_pkt_len
#        0,  # bck_max_pkt_len
#        0,  # bck_min_pkt_len
#        0,  # bck_frq_pkt
#        0,  # bck_avg_ttl
#        1,  # fwd_qt_pkt
#        0,  # fwd_qt_fin_fl
#        1,  # fwd_qt_syn_fl
#        0,  # fwd_qt_res_fl
#        0,  # fwd_qt_psh_fl
#        0,  # fwd_qt_ack_fl
#        0,  # fwd_qt_urg_fl
#        0,  # fwd_qt_ecn_fl
#        0,  # fwd_qt_cwr_fl
#        0,  # fwd_avg_hdr_len
#        74,  # fwd_avg_pkt_len
#        74,  # fwd_max_pkt_len
#        74,  # fwd_min_pkt_len
#        1,  # fwd_frq_pkt
#        63,  # fwd_avg_ttl
#        0,  # tm_dur_s
#    ]
#    inv_key = (key[2], key[3], key[0], key[1], key[4])
#    ftrs = afg._generate_features_fivetuplebi(inv_key)
#    assert ftrs == expected
#
#    # Duration > 0
#    # Updating
#    # Third packet is another SYN TCP packet with same IPs and Ports
#    packet = capture[2]
#    afg._update_fivetuplebi(packet)
#    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183813)
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # fwd_qt_pkt
#        0,  # fwd_qt_fin_fl
#        2,  # fwd_qt_syn_fl
#        0,  # fwd_qt_res_fl
#        0,  # fwd_qt_psh_fl
#        0,  # fwd_qt_ack_fl
#        0,  # fwd_qt_urg_fl
#        0,  # fwd_qt_ecn_fl
#        0,  # fwd_qt_cwr_fl
#        0,  # fwd_avg_hdr_len
#        74,  # fwd_avg_pkt_len
#        74,  # fwd_max_pkt_len
#        74,  # fwd_min_pkt_len
#        2 / dur,  # fwd_frq_pkt
#        63,  # fwd_avg_ttl
#        0,  # bck_qt_pkt
#        0,  # bck_qt_fin_fl
#        0,  # bck_qt_syn_fl
#        0,  # bck_qt_res_fl
#        0,  # bck_qt_psh_fl
#        0,  # bck_qt_ack_fl
#        0,  # bck_qt_urg_fl
#        0,  # bck_qt_ecn_fl
#        0,  # bck_qt_cwr_fl
#        0,  # bck_avg_hdr_len
#        0,  # bck_avg_pkt_len
#        0,  # bck_max_pkt_len
#        0,  # bck_min_pkt_len
#        0 / dur,  # bck_frq_pkt
#        0,  # bck_avg_ttl
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_fivetuplebi(key)
#    assert ftrs == expected
#
#    # Using now datetime.
#    new_timestamp = datetime.now()
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # fwd_qt_pkt
#        0,  # fwd_qt_fin_fl
#        2,  # fwd_qt_syn_fl
#        0,  # fwd_qt_res_fl
#        0,  # fwd_qt_psh_fl
#        0,  # fwd_qt_ack_fl
#        0,  # fwd_qt_urg_fl
#        0,  # fwd_qt_ecn_fl
#        0,  # fwd_qt_cwr_fl
#        0,  # fwd_avg_hdr_len
#        74,  # fwd_avg_pkt_len
#        74,  # fwd_max_pkt_len
#        74,  # fwd_min_pkt_len
#        2 / dur,  # fwd_frq_pkt
#        63,  # fwd_avg_ttl
#        0,  # bck_qt_pkt
#        0,  # bck_qt_fin_fl
#        0,  # bck_qt_syn_fl
#        0,  # bck_qt_res_fl
#        0,  # bck_qt_psh_fl
#        0,  # bck_qt_ack_fl
#        0,  # bck_qt_urg_fl
#        0,  # bck_qt_ecn_fl
#        0,  # bck_qt_cwr_fl
#        0,  # bck_avg_hdr_len
#        0,  # bck_avg_pkt_len
#        0,  # bck_max_pkt_len
#        0,  # bck_min_pkt_len
#        0 / dur,  # bck_frq_pkt
#        0,  # bck_avg_ttl
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_fivetuplebi(key, now=True)
#    assert np.isclose(ftrs, expected).all()
#
#    # Backward features
#    # Updating
#    # Fourth packet is a SYN ACK response TCP packet with inverted IPs and
#    packet = capture[3]
#    afg._update_fivetuplebi(packet)
#    new_timestamp = datetime(2018, 12, 1, 13, 17, 11, 183932)
#    dur = (new_timestamp - timestamp).total_seconds()
#    expected = [
#        2,  # fwd_qt_pkt
#        0,  # fwd_qt_fin_fl
#        2,  # fwd_qt_syn_fl
#        0,  # fwd_qt_res_fl
#        0,  # fwd_qt_psh_fl
#        0,  # fwd_qt_ack_fl
#        0,  # fwd_qt_urg_fl
#        0,  # fwd_qt_ecn_fl
#        0,  # fwd_qt_cwr_fl
#        0,  # fwd_avg_hdr_len
#        74,  # fwd_avg_pkt_len
#        74,  # fwd_max_pkt_len
#        74,  # fwd_min_pkt_len
#        2 / dur,  # fwd_frq_pkt
#        63,  # fwd_avg_ttl
#        1,  # bck_qt_pkt
#        0,  # bck_qt_fin_fl
#        1,  # bck_qt_syn_fl
#        0,  # bck_qt_res_fl
#        0,  # bck_qt_psh_fl
#        1,  # bck_qt_ack_fl
#        0,  # bck_qt_urg_fl
#        0,  # bck_qt_ecn_fl
#        0,  # bck_qt_cwr_fl
#        0,  # bck_avg_hdr_len
#        74,  # bck_avg_pkt_len
#        74,  # bck_max_pkt_len
#        74,  # bck_min_pkt_len
#        1 / dur,  # bck_frq_pkt
#        64,  # bck_avg_ttl
#        dur,  # tm_dur_s
#    ]
#    ftrs = afg._generate_features_fivetuplebi(key)
#    assert np.isclose(ftrs, expected).all()
#
#    # Zero forward packets on existing flow
#    ip_src_1 = LayerFieldsContainer('192.168.0.1')
#    ip_dst_1 = LayerFieldsContainer('192.168.0.2')
#    src_port_1 = '80'
#    dst_port_1 = '80'
#    protocol_1 = 'TCP'
#    key_1 = (ip_src_1, src_port_1, ip_dst_1, dst_port_1, protocol_1)
#    t5_1 = FiveTupleBidirectionalNode()
#    memory_fivetup_1 = {key_1: t5_1}
#    afg_1 = AnubisFG(memory_fivetup=memory_fivetup_1)
#    ftrs = afg_1._generate_features_fivetuplebi(key_1)
#    assert ftrs == [0] * n_features
#
#    
#
#
#def test_generate_features():
#    capture = rdpcap('tests/data/test_100_rows.pcap')
#    # Flow to be tested.
#    packet = capture[1]
#    ip_src = packet.ip.src
#    ip_dst = packet.ip.dst
#    src_port = int(packet[packet.transport_layer].srcport)
#    dst_port = int(packet[packet.transport_layer].dstport)
#    protocol = packet.transport_layer
#    # Will be tested considering all possible sets of attributes.
#    for bidir in [True, False]:
#        for onlytwo in [True, False]:
#            for onlyfive in set([not onlytwo, False]):
#                afg_1 = AnubisFG(bidirectional=bidir, only_twotuple=onlytwo,
#                                 only_fivetuple=onlyfive)
#                # Will be tested along 3 updates.
#                for i in range(1, 4):
#                    packet = capture[i]
#                    afg_1.update(packet)
#                    if bidir:
#                        if onlytwo:
#                            key = (ip_src, ip_dst)
#                            assert afg_1.generate_features(
#                                key) == afg_1._generate_features_twotuplebi(key)
#                        elif onlyfive:
#                            key = (
#                                ip_src, src_port, ip_dst, dst_port, protocol)
#                            assert afg_1.generate_features(
#                                key) == afg_1._generate_features_fivetuplebi(key)
#                        else:
#                            key2 = (ip_src, ip_dst)
#                            key5 = (
#                                ip_src, src_port, ip_dst, dst_port, protocol)
#                            ftrs_1 = afg_1.generate_features(key5)
#                            ftrs_2 = afg_1._generate_features_twotuplebi(
#                                key2) + afg_1._generate_features_fivetuplebi(key5)
#                            assert ftrs_1 == ftrs_2
#                    else:
#                        if onlytwo:
#                            key = (ip_src, ip_dst)
#                            assert afg_1.generate_features(
#                                key) == afg_1._generate_features_twotupleuni(key)
#                        elif onlyfive:
#                            key = (
#                                ip_src, src_port, ip_dst, dst_port, protocol)
#                            assert afg_1.generate_features(
#                                key) == afg_1._generate_features_fivetupleuni(key)
#                        else:
#                            key2 = (ip_src, ip_dst)
#                            key5 = (
#                                ip_src, src_port, ip_dst, dst_port, protocol)
#                            ftrs_1 = afg_1.generate_features(key5)
#                            ftrs_2 = afg_1._generate_features_twotupleuni(
#                                key2) + afg_1._generate_features_fivetupleuni(key5)
#                            assert ftrs_1 == ftrs_2
#
#    
#