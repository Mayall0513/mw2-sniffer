#pragma once

#include "infpod.hpp"

#include <string>
#include <stdexcept>

#include <iostream>
#include <format>
#include <sstream>

template<typename T>
concept plain_data = std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T>;

template<typename T>
concept plain_integral_data = std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T> && std::integral<T>;

class packet_parser {
private:
	const uint8_t * m_buffer;
	const char * m_char_buffer;
	size_t m_size;

	size_t m_byte_cursor;
	size_t m_bit_cursor;
	uint8_t m_bits_read;

public:
	packet_parser(const uint8_t * buffer, size_t size);

	inline static uint8_t get_byte_mask(uint8_t offset, uint8_t bits) {
		return ((1U << bits) - 1) << offset;
	}

	template<plain_integral_data T>
	inline T read_bits(size_t bits) {
		if ((sizeof(T) * 8) < bits) {
			throw std::runtime_error("Buffer not large enough to hold bits");
		}

		if (false == this->has_remaining_data(0U, bits)) {
			throw std::runtime_error("Not enough data remaining");
		}

		T buffer {};

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


			uint8_t mask = this->get_byte_mask(this->m_bits_read, remaining_bits_in_byte_to_read);
			buffer += static_cast<T>((this->m_buffer[this->m_bit_cursor] & mask) >> m_bits_read) << (bits - remaining_bits_in_byte_to_read);

			this->m_bits_read += remaining_bits_in_byte_to_read;
			bits -= remaining_bits_in_byte_to_read;
		}

		return buffer;
	}

	template<plain_data T>
	inline T read_bytes(size_t bytes) {
		if (sizeof(T) < bytes) {
			throw std::runtime_error("Buffer not large enough to hold bytes");
		}

		if (false == this->has_remaining_data(bytes)) {
			throw std::runtime_error("Not enough data remaining");
		}

		T buffer {};

		std::memcpy(&buffer, this->m_buffer + this->m_byte_cursor + (sizeof(T) - bytes), bytes);
		this->m_byte_cursor += bytes;

		return buffer;
	}

	std::string read_string();

	void skip_bits(size_t bits);
	void skip_bytes(size_t bytes);

	bool has_remaining_data(size_t bytes, size_t bits = 0U) const;
};

