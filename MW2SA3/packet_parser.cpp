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
	std::string output(this->m_char_buffer + this->m_byte_cursor);
	this->m_byte_cursor += output.size() + 1;
	return output;
}

void packet_parser::skip_bits(size_t bits) {
	while (bits > 0) {
		if (0 == this->m_bits_read) {
			if (this->m_bit_cursor < this->m_byte_cursor) {
				this->m_bit_cursor = this->m_byte_cursor;
			}

			this->m_byte_cursor++;
		}
		else if (8 == this->m_bits_read) {
			this->m_bit_cursor = this->m_byte_cursor;
			this->m_byte_cursor++;
			this->m_bits_read = 0;
		}

		uint8_t remaining_bits_in_byte_to_read = 8 - this->m_bits_read;
		if (remaining_bits_in_byte_to_read > bits) {
			remaining_bits_in_byte_to_read = static_cast<uint8_t>(bits);
		}

		this->m_bits_read += remaining_bits_in_byte_to_read;
		bits -= remaining_bits_in_byte_to_read;
	}
}

void packet_parser::skip_bytes(size_t bytes) {
	this->m_byte_cursor += bytes;
}

bool packet_parser::has_remaining_data(size_t bytes, size_t bits) const {
	if (8U - this->m_bits_read < bits) {
		bits -= 8U - this->m_bits_read;
		bytes += (bits + 7) / 8;
	}

	return bytes <= this->m_size - this->m_byte_cursor;
}

