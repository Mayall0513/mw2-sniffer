#include "packet_parser.hpp"

packet_parser::packet_parser(const uint8_t * buffer, size_t size) {
	this->m_buffer = buffer;
	this->m_char_buffer = reinterpret_cast<const char *>(buffer);
	this->m_size = size;

	this->m_byte_cursor = 0;
	this->m_bit_cursor = 0;
	this->m_bits_read = 0;
}

std::string packet_parser::read_string() {
	std::string output(m_char_buffer + this->m_byte_cursor);
	this->m_byte_cursor += output.size() + 1;
	return output;
}

bool packet_parser::read_bit() {
	if (0 == this->m_bits_read && this->m_bit_cursor < this->m_byte_cursor) {
		this->m_bit_cursor = this->m_byte_cursor;
		this->m_byte_cursor++;
	}
	else if (8 == this->m_bits_read) {
		this->m_bit_cursor = this->m_byte_cursor;
		this->m_byte_cursor++;
		this->m_bits_read = 0;
	}

	bool output = static_cast<bool>((m_buffer[m_bit_cursor] >> m_bits_read) & 1);
	this->m_bits_read++;
	return output;
}

uint8_t packet_parser::read_bits_as_uint8(size_t count) {
	uint8_t buffer = 0;
	for (int i = 0; i < count; i++) {
		buffer += read_bit() << i;
	}

	return buffer;
}

uint16_t packet_parser::read_bits_as_uint16(size_t count) {
	uint16_t buffer = 0;
	for (int i = 0; i < count; i++) {
		buffer += read_bit() << i;
	}

	return buffer;
}

uint32_t packet_parser::read_bits_as_uint32(size_t count) {
	uint32_t buffer = 0;
	for (int i = 0; i < count; i++) {
		buffer += read_bit() << i;
	}

	return buffer;
}

uint64_t packet_parser::read_bits_as_uint64(size_t count) {
	uint64_t buffer = 0;
	for (int i = 0; i < count; i++) {
		buffer += read_bit() << i;
	}

	return buffer;
}

uint8_t packet_parser::read_uint8() {
	char output = this->m_buffer[m_byte_cursor];
	m_byte_cursor += sizeof(uint8_t);
	return output;
}

uint16_t packet_parser::read_uint16() {
	uint16_t output = *reinterpret_cast<const uint16_t *>(this->m_buffer + this->m_byte_cursor);
	this->m_byte_cursor += sizeof(uint16_t);
	return output;
}

uint32_t packet_parser::read_uint32() {
	uint32_t output = *reinterpret_cast<const uint32_t *>(this->m_buffer + this->m_byte_cursor);
	this->m_byte_cursor += sizeof(uint32_t);
	return output;
}

ipv4_address_t packet_parser::read_ipv4_address() {
	ipv4_address_t output = *reinterpret_cast<const ipv4_address_t *>(this->m_buffer + this->m_byte_cursor);
	this->m_byte_cursor += sizeof(ipv4_address_t);
	return output;
}

uint64_t packet_parser::read_uint64() {
	uint64_t output = *reinterpret_cast<const uint64_t *>(this->m_buffer + this->m_byte_cursor);
	this->m_byte_cursor += sizeof(uint64_t);
	return output;
}

void packet_parser::skip_bits(size_t bits) {
	for (size_t i = 0; i < bits; i++) {
		if (0 == this->m_bits_read && this->m_bit_cursor < this->m_byte_cursor) {
			this->m_bit_cursor = this->m_byte_cursor;
			this->m_byte_cursor++;
		}
		else if (8 == this->m_bits_read) {
			this->m_bit_cursor = this->m_byte_cursor;
			this->m_byte_cursor++;
			this->m_bits_read = 0;
		}
	}
}

void packet_parser::skip_bytes(size_t bytes) {
	this->m_byte_cursor += bytes;
}

bool packet_parser::has_remaining_data(size_t bytes, size_t bits) const {
	size_t bit_bytes = (bits + this->m_bit_cursor) / 8;
	return this->m_size >= (this->m_byte_cursor + bytes + bit_bytes);
}