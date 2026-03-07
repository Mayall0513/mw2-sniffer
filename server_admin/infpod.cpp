#include "infpod.hpp"

#include <format>
#include <winsock2.h>

std::string ipv4_address_t::to_string() const {
	return std::format("{:d}.{:d}.{:d}.{:d}", this->m_data[0], this->m_data[1], this->m_data[2], this->m_data[3]);
}

uint8_t ipv4_header_t::header_length_bytes() const {
	return (this->m_first & 0x0F) * 4;
}

uint16_t ipv4_header_t::total_length() const {
	return ntohs(this->m_total_length);
}

uint16_t udp_header_t::source() const {
	return ntohs(this->m_source);
}

uint16_t udp_header_t::destination() const {
	return ntohs(this->m_destination);
}

uint16_t udp_header_t::length() const {
	return ntohs(this->m_length);
}

uint16_t udp_header_t::checksum() const {
	return ntohs(this->m_checksum);
}