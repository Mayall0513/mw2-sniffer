#pragma once

#include <stdint.h>
#include <string>

// fixed size 6 bytes
struct mac_address_t {
	// POD
private:
	uint8_t m_data[6];

public:
	std::string serialise_readable() const;
};

// fixed size 4 bytes
struct ipv4_address_t {
	// POD
private:
	uint8_t m_data[4];

public:
	std::string serialise_readable() const;
	uint32_t packed_int32() const;
};

// fixed size 14 bytes
struct ethernet_header_t {
	// POD
private:
	const mac_address_t m_destination;
	const mac_address_t m_source;
	const uint16_t m_type;

public:
	std::string serialise_readable() const;
};

// fixed size 20 bytes, does not include options
struct ipv4_header_t {
	// POD
private:
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

public:
	uint8_t header_length_bytes() const;
	uint16_t total_length() const;
	std::string serialise_readable() const;
	ipv4_address_t source() const;
	ipv4_address_t destination() const;
};

// fixed size 8 bytes
struct udp_header_t {
	// POD
private:
	uint16_t m_source;
	uint16_t m_destination;
	uint16_t m_length;
	uint16_t m_checksum;

public:
	uint16_t source() const;
	uint16_t destination() const;
	uint16_t length() const;
	uint16_t checksum() const;
	std::string serialise_readable() const;
};