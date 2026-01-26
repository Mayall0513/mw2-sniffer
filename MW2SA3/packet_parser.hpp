#pragma once

#include "infpod.hpp"
#include <string>

class packet_parser {
private:
	const uint8_t * m_buffer;
	const char * m_char_buffer;
	size_t m_size;

	size_t m_byte_cursor;
	size_t m_bit_cursor;
	size_t m_bits_read;

public:
	packet_parser(const uint8_t * buffer, size_t size);

	bool read_bit();
	uint8_t read_bits_as_uint8(size_t count);
	uint16_t read_bits_as_uint16(size_t count);
	uint32_t read_bits_as_uint32(size_t count);
	uint64_t read_bits_as_uint64(size_t count);
	uint8_t read_uint8();
	uint16_t read_uint16();
	uint32_t read_uint32();
	uint64_t read_uint64();
	std::string read_string();
	ipv4_address_t read_ipv4_address();

	void skip_bits(size_t bits);
	void skip_bytes(size_t bytes);

	bool has_remaining_data(size_t bytes, size_t bits = 0) const;
};

