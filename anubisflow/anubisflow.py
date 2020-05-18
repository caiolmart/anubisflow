from typing import Dict, List, Tuple, Union
from datetime import datetime

from pyshark.packet.fields import LayerFieldsContainer
from pyshark.packet.packet import Packet
from .nodes import TwoTupleUnidirectionalNode, TwoTupleBidirectionalNode, FiveTupleUnidirectionalNode, FiveTupleBidirectionalNode


def add_to_counter(counter, key, val=1):
    if key in counter:
        counter[key] += val
    else:
        counter[key] = val


def zero_if_not_exists(counter, key):
    if key in counter:
        return counter[key]
    return 0


class AnubisFG:
    '''
    Class stores information in memory and generate features of flows.

    It can update the stored information from new packets and extract features
    from fluxes from this stored information.

    It keeps the information on two dictionaries, one for the two-tuple flow
    (IP Source, IP Destination) and one for the 5-tuple flow (IP Source, Port
    Source, IP Destination, Port Destination, Protocol). Optionally it can
    store information on the bidirection flows.

    Parameters
    ----------
    bidirectional: `bool`
        Wheter or not to consider the bidirectional flow (default True).
    only_twotuple: `bool`
        Wheter or not to store information of only the two-tuple flows
        (default False).
    only_fivetuple: `bool`
        Wheter or not to store information of only the five-tuple flows
        (default False).

    Attributes
    ----------
    memory_twotup: `dict`
        The dictionary with the information of the flows. Has key (IP Source,
        IP Destination), a tuple with two
        pyshark.packet.fields.LayerFieldsContainer's, and value a
        TwoTupleUnidirectionalNode of TwoTupleBidirectionalNode object,
        depeding on the choice of the bidirectional parameter.
    memory_fivetup: `dict`
        The dictionary with the information of the flows. Has key (IP Source,
        Source Port, IP Destination, Destination Port, Protocol), a tuple with
        five elements (pyshark.packet.fields.LayerFieldsContainer,
        pyshark.packet.fields.LayerFieldsContainer,
        pyshark.packet.fields.LayerFieldsContainer,
        pyshark.packet.fields.LayerFieldsContainer, str), and value a
        FiveTupleUnidirectionalNode or FiveTupleBidirectionalNode object,
        depeding on the choice of the bidirectional parameter.

    Examples
    --------
    >>> afg = AnubisFG()

    Creates a AnubisFG object.

    >>> afg.update(packet)

    Updates the memories with a packet.

    >>> afg.generate_features(five_tuple=(ip_src, port_src, ip_dst, port_dst,
                                          protocol))
    list_of_features

    Extract the features of both the two-tuple and the five-tuple flows with the
    stored information.

    '''

    def __init__(self,
                 bidirectional=True,
                 only_twotuple=False,
                 only_fivetuple=False,
                 memory_twotup: Dict[Tuple[LayerFieldsContainer,
                                           LayerFieldsContainer],
                                     Union[TwoTupleUnidirectionalNode,
                                           TwoTupleBidirectionalNode]] = None,
                 memory_fivetup: Dict[Tuple[LayerFieldsContainer,
                                            LayerFieldsContainer,
                                            LayerFieldsContainer,
                                            LayerFieldsContainer,
                                            str],
                                      Union[FiveTupleUnidirectionalNode,
                                            FiveTupleUnidirectionalNode]] = None):
        msg = "Parameters only_twotuple and only_fivetuple can't be mutually " \
              "True"
        assert not (only_twotuple and only_fivetuple), msg

        if memory_twotup is None and not only_fivetuple:
            self.memory_twotup = dict()
        elif not only_fivetuple:
            msg = 'AssertionError: memory_twotup must be of type ' \
                  'Dict[Tuple[LayerFieldsContainer, LayerFieldsContainer], ' \
                  'TwoTupleUnidirectionalNode]'
            assert isinstance(memory_twotup, dict), msg
            for item in memory_twotup.items():
                assert isinstance(item[0], tuple), msg
                assert isinstance(item[0][0], LayerFieldsContainer), msg
                assert isinstance(item[0][1], LayerFieldsContainer), msg
                if bidirectional:
                    assert isinstance(item[1], TwoTupleBidirectionalNode), msg
                else:
                    assert isinstance(item[1], TwoTupleUnidirectionalNode), msg
            self.memory_twotup = memory_twotup
        else:
            self.memory_twotup = None

        if memory_fivetup is None and not only_twotuple:
            self.memory_fivetup = dict()
        elif not only_twotuple:
            msg = 'AssertionError: memory_fivetup must be of type ' \
                  'Dict[Tuple[LayerFieldsContainer, LayerFieldsContainer, ' \
                  'LayerFieldsContainer, LayerFieldsContainer, str], ' \
                  'Union[FiveTupleUnidirectionalNode, ' \
                  'FiveTupleBidirectionalNode]]'
            assert isinstance(memory_fivetup, dict), msg
            for item in memory_fivetup.items():
                assert isinstance(item[0], tuple), msg
                assert isinstance(item[0][0], LayerFieldsContainer), msg
                assert isinstance(item[0][1], LayerFieldsContainer), msg
                assert isinstance(item[0][2], LayerFieldsContainer), msg
                assert isinstance(item[0][3], LayerFieldsContainer), msg
                assert isinstance(item[0][4], str), msg
                if bidirectional:
                    assert isinstance(item[1], FiveTupleBidirectionalNode), msg
                else:
                    assert isinstance(
                        item[1], FiveTupleUnidirectionalNode), msg
            self.memory_fivetup = memory_fivetup
        else:
            self.memory_fivetup = None

    def _update_twotupleuni(self, packet: Packet, ignore_errors=True):
        ''' Method updates the two tuple unidirectional memory with a pyshark
        packet.

        Parameters
        ----------
        packet: `pyshark.packet.packet.Packet`
            The packet to be inserted in memory.

        ignore_errors: `bool`
            Whether or not to ignore invalid packets (only packets with IP
            Source, IP Destination, Source Port and Destination Port are valid -
            STP Packets are invalid for example). (default=True)
        '''
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            timestamp = packet.sniff_time
            src_port = int(packet[packet.transport_layer].srcport)
            dst_port = int(packet[packet.transport_layer].dstport)
            protocol = packet.transport_layer
            length = int(packet.length)
        except AttributeError as err:
            if ignore_errors:
                return
            err.args = ('Attribute ip not in packet', )
            raise

        # Not all packets have IP headers
        try:
            hdr_length = int(packet.ip.hdr_length)
        except AttributeError:
            hdr_length = 0
        # Only works for tcp packets
        try:
            ack = int(packet.tcp.flags_ack)
            cwr = int(packet.tcp.flags_cwr)
            ecn = int(packet.tcp.flags_ecn)
            fin = int(packet.tcp.flags_fin)
            res = int(packet.tcp.flags_res)
            syn = int(packet.tcp.flags_syn)
            urg = int(packet.tcp.flags_urg)
            psh = int(packet.tcp.flags_push)
        except AttributeError:
            ack = 0
            cwr = 0
            ecn = 0
            fin = 0
            res = 0
            syn = 0
            urg = 0
            psh = 0
        key = (ip_src, ip_dst)
        if key in self.memory_twotup:
            self.memory_twotup[key].lst_timestamp = timestamp
            self.memory_twotup[key].set_src_ports.add(src_port)
            self.memory_twotup[key].set_dst_ports.add(dst_port)
            add_to_counter(self.memory_twotup[key].pkt_protocol_counter,
                           protocol)
            self.memory_twotup[key].tot_packet_len += length
            self.memory_twotup[key].tot_header_len += hdr_length
            self.memory_twotup[key].pkt_flag_counter[0] += fin
            self.memory_twotup[key].pkt_flag_counter[1] += syn
            self.memory_twotup[key].pkt_flag_counter[2] += res
            self.memory_twotup[key].pkt_flag_counter[3] += psh
            self.memory_twotup[key].pkt_flag_counter[4] += ack
            self.memory_twotup[key].pkt_flag_counter[5] += urg
            self.memory_twotup[key].pkt_flag_counter[6] += ecn
            self.memory_twotup[key].pkt_flag_counter[7] += cwr
        else:
            node_dict = {
                'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'set_src_ports': {src_port},
                'set_dst_ports': {dst_port},
                'pkt_flag_counter': [
                    fin,
                    syn,
                    res,
                    psh,
                    ack,
                    urg,
                    ecn,
                    cwr],
                'pkt_protocol_counter': {
                    protocol: 1},
                'tot_header_len': hdr_length,
                'tot_packet_len': length}
            node = TwoTupleUnidirectionalNode(**node_dict)
            self.memory_twotup[key] = node

    def _update_twotuplebi(self, packet: Packet, ignore_errors=True):
        ''' Method updates the two tuple unidirectional memory with a pyshark
        packet.

        Parameters
        ----------
        packet: `pyshark.packet.packet.Packet`
            The packet to be inserted in memory.

        ignore_errors: `bool`
            Whether or not to ignore invalid packets (only packets with IP
            Source, IP Destination, Source Port and Destination Port are valid -
            STP Packets are invalid for example). (default=True)
        '''
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            timestamp = packet.sniff_time
            src_port = int(packet[packet.transport_layer].srcport)
            dst_port = int(packet[packet.transport_layer].dstport)
            protocol = packet.transport_layer
            length = int(packet.length)
        except AttributeError as err:
            if ignore_errors:
                return
            err.args = ('Attribute ip not in packet', )
            raise

        # Not all packets have IP headers
        try:
            hdr_length = int(packet.ip.hdr_length)
        except AttributeError:
            hdr_length = 0
        # Only works for tcp packets
        try:
            ack = int(packet.tcp.flags_ack)
            cwr = int(packet.tcp.flags_cwr)
            ecn = int(packet.tcp.flags_ecn)
            fin = int(packet.tcp.flags_fin)
            res = int(packet.tcp.flags_res)
            syn = int(packet.tcp.flags_syn)
            urg = int(packet.tcp.flags_urg)
            psh = int(packet.tcp.flags_push)
        except AttributeError:
            ack = 0
            cwr = 0
            ecn = 0
            fin = 0
            res = 0
            syn = 0
            urg = 0
            psh = 0
        if (ip_src, ip_dst) in self.memory_twotup:
            prefix = 'fwd'
            key = (ip_src, ip_dst)
        elif (ip_dst, ip_src) in self.memory_twotup:
            prefix = 'bck'
            key = (ip_dst, ip_src)
        else:
            node_dict = {
                'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'fwd_set_src_ports': {src_port},
                'fwd_set_dst_ports': {dst_port},
                'fwd_pkt_flag_counter': [
                    fin,
                    syn,
                    res,
                    psh,
                    ack,
                    urg,
                    ecn,
                    cwr],
                'fwd_pkt_protocol_counter': {
                    protocol: 1},
                'fwd_tot_header_len': hdr_length,
                'fwd_tot_packet_len': length}
            node = TwoTupleBidirectionalNode(**node_dict)
            self.memory_twotup[(ip_src, ip_dst)] = node
            return

        self.memory_twotup[key].__dict__[f'lst_timestamp'] = timestamp
        self.memory_twotup[key].__dict__[
            f'{prefix}_set_src_ports'].add(src_port)
        self.memory_twotup[key].__dict__[
            f'{prefix}_set_dst_ports'].add(dst_port)
        add_to_counter(self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_protocol_counter'], protocol)
        self.memory_twotup[key].__dict__[f'{prefix}_tot_packet_len'] += length
        self.memory_twotup[key].__dict__[
            f'{prefix}_tot_header_len'] += hdr_length
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][0] += fin
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][1] += syn
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][2] += res
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][3] += psh
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][4] += ack
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][5] += urg
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][6] += ecn
        self.memory_twotup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][7] += cwr

    def _update_fivetupleuni(self, packet: Packet, ignore_errors=True):
        ''' Method updates the two tuple unidirectional memory with a pyshark
        packet.

        Parameters
        ----------
        packet: `pyshark.packet.packet.Packet`
            The packet to be inserted in memory.

        ignore_errors: `bool`
            Whether or not to ignore invalid packets (only packets with IP
            Source, IP Destination, Source Port and Destination Port are valid -
            STP Packets are invalid for example). (default=True)
        '''
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            timestamp = packet.sniff_time
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
            protocol = packet.transport_layer
            length = int(packet.length)
            ttl = int(packet.ip.ttl)
        except AttributeError as err:
            if ignore_errors:
                return
            err.args = ('Attribute ip not in packet', )
            raise

        # Not all packets have IP headers
        try:
            hdr_length = int(packet.ip.hdr_length)
        except AttributeError:
            hdr_length = 0
        # Only works for tcp packets
        try:
            ack = int(packet.tcp.flags_ack)
            cwr = int(packet.tcp.flags_cwr)
            ecn = int(packet.tcp.flags_ecn)
            fin = int(packet.tcp.flags_fin)
            res = int(packet.tcp.flags_res)
            syn = int(packet.tcp.flags_syn)
            urg = int(packet.tcp.flags_urg)
            psh = int(packet.tcp.flags_push)
        except AttributeError:
            ack = 0
            cwr = 0
            ecn = 0
            fin = 0
            res = 0
            syn = 0
            urg = 0
            psh = 0
        key = (ip_src, src_port, ip_dst, dst_port, protocol)
        if key in self.memory_fivetup:
            max_pkt_len = max(length, self.memory_fivetup[key].max_pkt_len)
            min_pkt_len = min(length, self.memory_fivetup[key].min_pkt_len)

            self.memory_fivetup[key].lst_timestamp = timestamp
            self.memory_fivetup[key].tot_pkt += 1
            self.memory_fivetup[key].tot_packet_len += length
            self.memory_fivetup[key].tot_header_len += hdr_length
            self.memory_fivetup[key].max_pkt_len = max_pkt_len
            self.memory_fivetup[key].min_pkt_len = min_pkt_len
            self.memory_fivetup[key].tot_ttl += ttl
            self.memory_fivetup[key].pkt_flag_counter[0] += fin
            self.memory_fivetup[key].pkt_flag_counter[1] += syn
            self.memory_fivetup[key].pkt_flag_counter[2] += res
            self.memory_fivetup[key].pkt_flag_counter[3] += psh
            self.memory_fivetup[key].pkt_flag_counter[4] += ack
            self.memory_fivetup[key].pkt_flag_counter[5] += urg
            self.memory_fivetup[key].pkt_flag_counter[6] += ecn
            self.memory_fivetup[key].pkt_flag_counter[7] += cwr
        else:
            node_dict = {
                'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'pkt_flag_counter': [
                    fin,
                    syn,
                    res,
                    psh,
                    ack,
                    urg,
                    ecn,
                    cwr],
                'tot_pkt': 1,
                'tot_header_len': hdr_length,
                'tot_packet_len': length,
                'max_pkt_len': length,
                'min_pkt_len': length,
                'tot_ttl': ttl}
            node = FiveTupleUnidirectionalNode(**node_dict)
            self.memory_fivetup[key] = node

    def _update_fivetuplebi(self, packet: Packet, ignore_errors=True):
        ''' Method updates the five tuple bidirectional memory with a pyshark
        packet.

        Parameters
        ----------
        packet: `pyshark.packet.packet.Packet`
            The packet to be inserted in memory.

        ignore_errors: `bool`
            Whether or not to ignore invalid packets (only packets with IP
            Source, IP Destination, Source Port and Destination Port are valid -
            STP Packets are invalid for example). (default=True)
        '''
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            timestamp = packet.sniff_time
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
            protocol = packet.transport_layer
            length = int(packet.length)
            ttl = int(packet.ip.ttl)
        except AttributeError as err:
            if ignore_errors:
                return
            err.args = ('Attribute ip not in packet', )
            raise

        # Not all packets have IP headers
        try:
            hdr_length = int(packet.ip.hdr_length)
        except AttributeError:
            hdr_length = 0
        # Only works for tcp packets
        try:
            ack = int(packet.tcp.flags_ack)
            cwr = int(packet.tcp.flags_cwr)
            ecn = int(packet.tcp.flags_ecn)
            fin = int(packet.tcp.flags_fin)
            res = int(packet.tcp.flags_res)
            syn = int(packet.tcp.flags_syn)
            urg = int(packet.tcp.flags_urg)
            psh = int(packet.tcp.flags_push)
        except AttributeError:
            ack = 0
            cwr = 0
            ecn = 0
            fin = 0
            res = 0
            syn = 0
            urg = 0
            psh = 0
        # Forward packet
        if (ip_src, src_port, ip_dst, dst_port,
                protocol) in self.memory_fivetup:
            prefix = 'fwd'
            key = (ip_src, src_port, ip_dst, dst_port, protocol)
        # Backward packet
        elif (ip_dst, dst_port, ip_src, src_port, protocol) in self.memory_fivetup:
            prefix = 'bck'
            key = (ip_dst, dst_port, ip_src, src_port, protocol)
        # New (forward) packet
        else:
            key = (ip_src, src_port, ip_dst, dst_port, protocol)
            node_dict = {
                'fst_timestamp': timestamp,
                'lst_timestamp': timestamp,
                'fwd_pkt_flag_counter': [
                    fin,
                    syn,
                    res,
                    psh,
                    ack,
                    urg,
                    ecn,
                    cwr],
                'fwd_tot_pkt': 1,
                'fwd_tot_header_len': hdr_length,
                'fwd_tot_packet_len': length,
                'fwd_max_pkt_len': length,
                'fwd_min_pkt_len': length,
                'fwd_tot_ttl': ttl}
            node = FiveTupleBidirectionalNode(**node_dict)
            self.memory_fivetup[key] = node
            return

        max_pkt_len = max(length,
                          self.memory_fivetup[key].__dict__[
                              f'{prefix}_max_pkt_len'])
        if self.memory_fivetup[key].__dict__[f'{prefix}_min_pkt_len'] > 0:
            min_pkt_len = min(length, self.memory_fivetup[key].__dict__[
                              f'{prefix}_min_pkt_len'])
        else:
            min_pkt_len = length
        self.memory_fivetup[key].__dict__['lst_timestamp'] = timestamp
        self.memory_fivetup[key].__dict__[
            f'{prefix}_tot_packet_len'] += length
        self.memory_fivetup[key].__dict__[
            f'{prefix}_tot_pkt'] += 1
        self.memory_fivetup[key].__dict__[
            f'{prefix}_max_pkt_len'] = max_pkt_len
        self.memory_fivetup[key].__dict__[
            f'{prefix}_min_pkt_len'] = min_pkt_len
        self.memory_fivetup[key].__dict__[
            f'{prefix}_tot_ttl'] += ttl
        self.memory_fivetup[key].__dict__[
            f'{prefix}_tot_header_len'] += hdr_length
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][0] += fin
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][1] += syn
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][2] += res
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][3] += psh
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][4] += ack
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][5] += urg
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][6] += ecn
        self.memory_fivetup[key].__dict__[
            f'{prefix}_pkt_flag_counter'][7] += cwr

    def _generate_features_twotupleuni(self,
                                       flow_key: Tuple[LayerFieldsContainer,
                                                       LayerFieldsContainer],
                                       now=False) -> List:
        ''' Extract features of the flow from the memory_twotup.

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
            qt_res_fl
            qt_psh_fl
            qt_ack_fl
            qt_urg_fl
            qt_ecn_fl
            qt_cwr_fl
            avg_hdr_len
            avg_pkt_len
            frq_pkt
            tm_dur_s
        '''
        n_features = 20
        if flow_key not in self.memory_twotup:
            return [0] * n_features
        mem = self.memory_twotup[flow_key]
        if now:
            lst_time = datetime.now()
        else:
            lst_time = mem.lst_timestamp
        qt_pkt = sum(mem.pkt_protocol_counter.values())
        duration_s = (lst_time - mem.fst_timestamp).total_seconds()
        if duration_s == 0:
            frq_pkt = qt_pkt
        else:
            frq_pkt = qt_pkt / duration_s
        return [
            qt_pkt,
            zero_if_not_exists(mem.pkt_protocol_counter, 'TCP'),
            zero_if_not_exists(mem.pkt_protocol_counter, 'UDP'),
            zero_if_not_exists(mem.pkt_protocol_counter, 'ICMP'),
            zero_if_not_exists(mem.pkt_protocol_counter, 'IP'),
            len(mem.pkt_protocol_counter),
            len(mem.set_src_ports),
            len(mem.set_dst_ports),
            mem.pkt_flag_counter[0],
            mem.pkt_flag_counter[1],
            mem.pkt_flag_counter[2],
            mem.pkt_flag_counter[3],
            mem.pkt_flag_counter[4],
            mem.pkt_flag_counter[5],
            mem.pkt_flag_counter[6],
            mem.pkt_flag_counter[7],
            mem.tot_header_len / qt_pkt,
            mem.tot_packet_len / qt_pkt,
            frq_pkt,
            duration_s,
        ]

    def _generate_features_twotuplebi(self,
                                      flow_key: Tuple[LayerFieldsContainer,
                                                      LayerFieldsContainer],
                                      now=False) -> List:
        ''' Extract features of the flow from the memory_twotup.

        Feature list:
        Forward:
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
            qt_res_fl
            qt_psh_fl
            qt_ack_fl
            qt_urg_fl
            qt_ecn_fl
            qt_cwr_fl
            avg_hdr_len
            avg_pkt_len
            frq_pkt

        Backward:
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
            qt_res_fl
            qt_psh_fl
            qt_ack_fl
            qt_urg_fl
            qt_ecn_fl
            qt_cwr_fl
            avg_hdr_len
            avg_pkt_len
            frq_pkt
        Non-directional:
            tm_dur_s

        '''

        n_features = 39

        if flow_key not in self.memory_twotup:
            return [0] * n_features
        mem = self.memory_twotup[flow_key]
        if now:
            lst_time = datetime.now()
        else:
            lst_time = mem.lst_timestamp

        fwd_qt_pkt = sum(mem.fwd_pkt_protocol_counter.values())
        bck_qt_pkt = sum(mem.bck_pkt_protocol_counter.values())

        duration_s = (lst_time - mem.fst_timestamp).total_seconds()
        if duration_s == 0:
            fwd_frq_pkt = fwd_qt_pkt
            bck_frq_pkt = bck_qt_pkt
        else:
            fwd_frq_pkt = fwd_qt_pkt / duration_s
            bck_frq_pkt = bck_qt_pkt / duration_s

        return [  # fwd
            fwd_qt_pkt,
            zero_if_not_exists(mem.fwd_pkt_protocol_counter, 'TCP'),
            zero_if_not_exists(mem.fwd_pkt_protocol_counter, 'UDP'),
            zero_if_not_exists(mem.fwd_pkt_protocol_counter, 'ICMP'),
            zero_if_not_exists(mem.fwd_pkt_protocol_counter, 'IP'),
            len(mem.fwd_pkt_protocol_counter),
            len(mem.fwd_set_src_ports),
            len(mem.fwd_set_dst_ports),
            mem.fwd_pkt_flag_counter[0],
            mem.fwd_pkt_flag_counter[1],
            mem.fwd_pkt_flag_counter[2],
            mem.fwd_pkt_flag_counter[3],
            mem.fwd_pkt_flag_counter[4],
            mem.fwd_pkt_flag_counter[5],
            mem.fwd_pkt_flag_counter[6],
            mem.fwd_pkt_flag_counter[7],
            mem.fwd_tot_header_len / fwd_qt_pkt,
            mem.fwd_tot_packet_len / fwd_qt_pkt,
            fwd_frq_pkt,
            # bck
            bck_qt_pkt,
            zero_if_not_exists(mem.bck_pkt_protocol_counter, 'TCP'),
            zero_if_not_exists(mem.bck_pkt_protocol_counter, 'UDP'),
            zero_if_not_exists(mem.bck_pkt_protocol_counter, 'ICMP'),
            zero_if_not_exists(mem.bck_pkt_protocol_counter, 'IP'),
            len(mem.bck_pkt_protocol_counter),
            len(mem.bck_set_src_ports),
            len(mem.bck_set_dst_ports),
            mem.bck_pkt_flag_counter[0],
            mem.bck_pkt_flag_counter[1],
            mem.bck_pkt_flag_counter[2],
            mem.bck_pkt_flag_counter[3],
            mem.bck_pkt_flag_counter[4],
            mem.bck_pkt_flag_counter[5],
            mem.bck_pkt_flag_counter[6],
            mem.bck_pkt_flag_counter[7],
            mem.bck_tot_header_len / bck_qt_pkt,
            mem.bck_tot_packet_len / bck_qt_pkt,
            bck_frq_pkt,
            # non-directional
            duration_s,
        ]

    def _generate_features_fivetupleuni(self,
                                        flow_key: Tuple[LayerFieldsContainer,
                                                        LayerFieldsContainer,
                                                        LayerFieldsContainer,
                                                        LayerFieldsContainer,
                                                        str],
                                        now=False) -> List:
        ''' Extract features of the flow from the memory_fivetup.

        Feature list:
            qt_pkt
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
            max_pkt_len
            min_pkt_len
            frq_pkt
            tm_dur_s
            avg_ttl
        '''
        n_features = 16
        if flow_key not in self.memory_fivetup:
            return [0] * n_features
        mem = self.memory_fivetup[flow_key]
        if now:
            lst_time = datetime.now()
        else:
            lst_time = mem.lst_timestamp
        duration_s = (lst_time - mem.fst_timestamp).total_seconds()
        if duration_s == 0:
            frq_pkt = mem.tot_pkt
        else:
            frq_pkt = mem.tot_pkt / duration_s
        return [
            mem.tot_pkt,
            mem.pkt_flag_counter[0],
            mem.pkt_flag_counter[1],
            mem.pkt_flag_counter[2],
            mem.pkt_flag_counter[3],
            mem.pkt_flag_counter[4],
            mem.pkt_flag_counter[5],
            mem.pkt_flag_counter[6],
            mem.pkt_flag_counter[7],
            mem.tot_header_len / mem.tot_pkt,
            mem.tot_packet_len / mem.tot_pkt,
            mem.max_pkt_len,
            mem.min_pkt_len,
            frq_pkt,
            duration_s,
            mem.tot_ttl / mem.tot_pkt
        ]

    def _generate_features_fivetuplebi(self,
                                       flow_key: Tuple[LayerFieldsContainer,
                                                       LayerFieldsContainer,
                                                       LayerFieldsContainer,
                                                       LayerFieldsContainer,
                                                       str],
                                       now=False) -> List:
        ''' Extract features of the flow from the memory_fivetup.

        Feature list:
        Forward
            fwd_qt_pkt
            fwd_qt_fin_fl
            fwd_qt_syn_fl
            fwd_qt_res_fl
            fwd_qt_psh_fl
            fwd_qt_ack_fl
            fwd_qt_urg_fl
            fwd_qt_ecn_fl
            fwd_qt_cwr_fl
            fwd_avg_hdr_len
            fwd_avg_pkt_len
            fwd_max_pkt_len
            fwd_min_pkt_len
            fwd_frq_pkt
            fwd_avg_ttl
        Backward
            bck_qt_pkt
            bck_qt_fin_fl
            bck_qt_syn_fl
            bck_qt_res_fl
            bck_qt_psh_fl
            bck_qt_ack_fl
            bck_qt_urg_fl
            bck_qt_ecn_fl
            bck_qt_cwr_fl
            bck_avg_hdr_len
            bck_avg_pkt_len
            bck_max_pkt_len
            bck_min_pkt_len
            bck_frq_pkt
            bck_avg_ttl
        Non-directional
            tm_dur_s
        '''
        n_features = 31
        if flow_key not in self.memory_fivetup:
            return [0] * n_features
        mem = self.memory_fivetup[flow_key]
        if now:
            lst_time = datetime.now()
        else:
            lst_time = mem.lst_timestamp
        duration_s = (lst_time - mem.fst_timestamp).total_seconds()
        if duration_s == 0:
            fwd_frq_pkt = mem.fwd_tot_pkt
            bck_frq_pkt = mem.bck_tot_pkt
        else:
            fwd_frq_pkt = mem.fwd_tot_pkt / duration_s
            bck_frq_pkt = mem.bck_tot_pkt / duration_s
        if mem.fwd_tot_pkt == 0:
            avg_fwd_header = 0
            avg_fwd_packet = 0
            avg_fwd_ttl = 0
        else:
            avg_fwd_header = mem.fwd_tot_header_len / mem.fwd_tot_pkt
            avg_fwd_packet = mem.fwd_tot_packet_len / mem.fwd_tot_pkt
            avg_fwd_ttl = mem.fwd_tot_ttl / mem.fwd_tot_pkt
        if mem.bck_tot_pkt == 0:
            avg_bck_header = 0
            avg_bck_packet = 0
            avg_bck_ttl = 0
        else:
            avg_bck_header = mem.bck_tot_header_len / mem.bck_tot_pkt
            avg_bck_packet = mem.bck_tot_packet_len / mem.bck_tot_pkt
            avg_bck_ttl = mem.bck_tot_ttl / mem.bck_tot_pkt

        return [
            # fwd
            mem.fwd_tot_pkt,
            mem.fwd_pkt_flag_counter[0],
            mem.fwd_pkt_flag_counter[1],
            mem.fwd_pkt_flag_counter[2],
            mem.fwd_pkt_flag_counter[3],
            mem.fwd_pkt_flag_counter[4],
            mem.fwd_pkt_flag_counter[5],
            mem.fwd_pkt_flag_counter[6],
            mem.fwd_pkt_flag_counter[7],
            avg_fwd_header,
            avg_fwd_packet,
            mem.fwd_max_pkt_len,
            mem.fwd_min_pkt_len,
            fwd_frq_pkt,
            avg_fwd_ttl,
            # bck
            mem.bck_tot_pkt,
            mem.bck_pkt_flag_counter[0],
            mem.bck_pkt_flag_counter[1],
            mem.bck_pkt_flag_counter[2],
            mem.bck_pkt_flag_counter[3],
            mem.bck_pkt_flag_counter[4],
            mem.bck_pkt_flag_counter[5],
            mem.bck_pkt_flag_counter[6],
            mem.bck_pkt_flag_counter[7],
            avg_bck_header,
            avg_bck_packet,
            mem.bck_max_pkt_len,
            mem.bck_min_pkt_len,
            bck_frq_pkt,
            avg_bck_ttl,
            # non-directional
            duration_s,
        ]
