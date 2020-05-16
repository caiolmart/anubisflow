# AnubisFlow

This is a tool designed to generate features to identify DDoS flows from `.pcap` files.

We begin by creating  a class that stores information about the flows, this class is continuously updated whenever a new packet passes through the network interface.

The class can store two dictionaries. One for the 2-tuple flow (a sequence of packets with the same values for _IP Source_, _IP Destination_) and one for the 5-tuple flow (a sequence of packets with same values for _IP Source_, _Port Source_, _IP Destination_, _Port Destination_, _Protocol_).

The goal is to generate and store features of the flows that may useful for identifying and blocking flows originated from a DDoS attack.

Here is the list of features of the 2-tuple flows we want to generate, and the attribute that stores the information to generate them.

| Feature | Description | TwoTupleNode attribute(s) |
| ------- | ----------- | --------------------- |
| qt_pkt | Amount of packets | pkt_protocol_counter |
| qt_pkt_tcp | Amount of TCP Packets | pkt_protocol_counter |
| qt_pkt_udp | Amount of UDP Packets | pkt_protocol_counter |
| qt_pkt_icmp | Amount of ICMP Packets | pkt_protocol_counter |
| qt_pkt_ip | Amount of IP Packets | pkt_protocol_counter |
| qt_prtcl | Amount of protocols | pkt_protocol_counter |
| qt_src_prt | Amount of Source Ports | set_src_ports |
| qt_dst_prt | Amount of Destination Ports | set_dst_ports |
| qt_fin_fl | Amount of FIN Flags | pkt_flag_counter |
| qt_syn_fl | Amount of SYN Flags | pkt_flag_counter |
| qt_psh_fl | Amount of PSH Flags | pkt_flag_counter |
| qt_ack_fl | Amount of ACK Flags | pkt_flag_counter |
| qt_urg_fl | Amount of URG Flags | pkt_flag_counter |
| qt_rst_fl | Amount of RST Flags | pkt_flag_counter |
| qt_ece_fl | Amount of ECE Flags | pkt_flag_counter |
| qt_cwr_fl | Amount of CWR Flags | pkt_flag_counter |
| avg_hdr_len | Average Header Size | tot_header_len + pkt_protocol_counter |
| avg_pkt_len | Average Packet Size | tot_packet_len + pkt_protocol_counter |
| frq_pkt | Frequency of packets | fst_timestamp (+ lst_timestamp) + pkt_protocol_counter |
| tm_dur_s | Time duration of the flow (s) | fst_timestamp (+ lst_timestamp)|
| qt_tos | Amount of IP Service Type | TODO |
| ttl_m | Average TTL | TODO |
| qt_do_not_frag | Amount of “Do Not Frag” Flags | TODO |
| qt_more_frag | Amount of “More Frag” Flags | TODO |
| fragment_offset_m | Average Fragment Offset | TODO |
| offset_m | Average Offset | TODO |
| qt_t_icmp | Amount of ICMP Types | TODO |
| qt_cdg_icmp | Amount of ICMP Codes | TODO |


## Testing

The tests are written using pytest and are in the folder `tests`.

To run the tests you may need to install `pytest-cov`:

```Shell
pytest --cov-report html --cov=anubisflow -v tests/
```
