import pytest
from datetime import datetime
import os
import pathlib

from pyshark.packet.fields import LayerFieldsContainer
from src.anubisflow import AnubisFG
from src.nodes import TwoTupleUnidirectionalNode


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
