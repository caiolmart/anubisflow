# AnubisFlow

This is a tool designed to generate features to identify DDoS flows from `.pcap` files.

The idea behind the tool is to have a class stores the information on the flows, and can be updated by any new packet passing through the network.

The class can stores two dictionaries. One for the 2-tuple flow (a sequence of packets with the same values for _IP Source_, _IP Destination_) and one for the 5-tuple flow (a sequence of packets with same values for _IP Source_, _Port Source_, _IP Destination_, _Port Destination_, _Protocol_).

The goal is to store, and readily generate features of the flows.

Here is the list of the features of the 2-tuple flows we want to generate, and the attribute that stores the information to generate them.

| Feature | Description | Tuple2Node attribute(s) |
| ------- | ----------- | --------------------- |
| qtd_pkt_tcp | Amount of TCP Packets | pkt_protocol_counter |
| qtd_pkt_udp | Amount of UDP Packets | pkt_protocol_counter |
| qtd_pkt_icmp | Amount of ICMP Packets | pkt_protocol_counter |
| qtd_pkt_ip | Amount of IP Packets | pkt_protocol_counter |
| qtd_src_port | Amount of Source Ports | set_src_ports |
| qtd_dst_port | Amount of Destination Ports | set_dst_ports |
| qtd_fin_flag | Amount of FIN Flags | pkt_flag_counter |
| qtd_syn_flag | Amount of SYN Flags | pkt_flag_counter |
| qtd_psh_flag | Amount of PSH Flags | pkt_flag_counter |
| qtd_ack_flag | Amount of ACK Flags | pkt_flag_counter |
| qtd_urg_flag | Amount of URG Flags | pkt_flag_counter |
| qtd_rst_flag | Amount of RST Flags | pkt_flag_counter |
| qtd_ece_flag | Amount of ECE Flags | pkt_flag_counter |
| qtd_cwr_flag | Amount of CWR Flags | pkt_flag_counter |
| header_len_m | Average Header Size | tot_header_len + pkt_protocol_counter |
| packet_len_m | Average Packet Size | tot_packet_len + pkt_protocol_counter |
| frq_packets | Frequency of packets | fst_timestamp + pkt_protocol_counter |
| qtd_tos | Amount of IP Service Type | ? |
| ttl_m | Average TTL | ? |
| qtd_do_not_frag | Amount of “Do Not Frag” Flags | ? |
| qtd_more_frag | Amount of “More Frag” Flags | ? |
| fragment_offset_m | Average Fragment Offset | ? |
| offset_m | Average Offset | ? |
| qtd_t_icmp | Amount of ICMP Types | ? |
| qtd_cdg_icmp | Amount of ICMP Codes | ? |
