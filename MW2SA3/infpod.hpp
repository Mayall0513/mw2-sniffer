#pragma once

#include <stdint.h>
#include <string>

#pragma pack(push, 1)
struct mac_address_t {
	uint8_t m_data[6];
};

struct ipv4_address_t {
	union {
		uint8_t m_data[4];
		uint32_t m_packed_data;
	};

	std::string to_string() const;
};

struct ethernet_header_t {
	mac_address_t m_destination;
	mac_address_t m_source;
	uint16_t m_type;
};

struct ipv4_header_t {
	uint8_t m_first;       // version + header length
	uint8_t m_second;      // service + congestion
	uint16_t m_total_length;
	uint16_t m_indentification;
	uint16_t m_third;      // flags + fragment offset
	uint8_t m_time_to_live;
	uint8_t m_protocol;
	uint16_t m_checksum;
	ipv4_address_t m_source;
	ipv4_address_t m_destiniation;

	uint8_t header_length_bytes() const;
	uint16_t total_length() const;
};

struct udp_header_t {
	uint16_t m_source;
	uint16_t m_destination;
	uint16_t m_length;
	uint16_t m_checksum;

	uint16_t source() const;
	uint16_t destination() const;
	uint16_t length() const;
	uint16_t checksum() const;
};

#pragma pack(pop)