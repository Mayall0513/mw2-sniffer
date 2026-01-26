#include "infpod.hpp"

#include <format>
#include <sstream>
#include <iomanip>
#include <winsock2.h>

std::string mac_address_t::serialise_readable() const {
	return std::format("mac_address ( {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} )", this->m_data[0], this->m_data[1], this->m_data[2], this->m_data[3], this->m_data[4], this->m_data[5]);
}

std::string ipv4_address_t::serialise_readable() const {
	return std::format("ipv4_address_t ( {:d}.{:d}.{:d}.{:d} )", this->m_data[0], this->m_data[1], this->m_data[2], this->m_data[3]);
}

uint32_t ipv4_address_t::packed_int32() const {
	return static_cast<uint32_t>(this->m_data[0]) + (static_cast<uint32_t>(this->m_data[1]) << 8) + (static_cast<uint32_t>(this->m_data[2]) << 16) + (static_cast<uint32_t>(this->m_data[3]) << 24);
}

std::string ethernet_header_t::serialise_readable() const {
	std::stringstream string_stream;

	string_stream << "ethernet_header_t {" << std::endl;
	string_stream << "\t" << "source: " << this->m_source.serialise_readable() << std::endl;
	string_stream << "\t" << "destination: " << this->m_destination.serialise_readable() << std::endl;
	string_stream << "\t" << "type:  " << ntohs(this->m_type) << std::endl;
	string_stream << "}";

	return string_stream.str();
}

uint8_t ipv4_header_t::header_length_bytes() const {
	return (this->m_first & 0x0F) * 4;
}

uint16_t ipv4_header_t::total_length() const {
	return ntohs(this->m_total_length);
}

std::string ipv4_header_t::serialise_readable() const {
	std::stringstream string_stream;

	string_stream << "ipv4_header_t {" << std::endl;
	string_stream << "\t" << "version: " << ((this->m_first & 0xF0) >> 4) << std::endl;
	string_stream << "\t" << "header_length: " << (int) this->header_length_bytes() << std::endl;
	string_stream << "\t" << "service: " << ((this->m_second & 0b11111100) >> 6) << std::endl;
	string_stream << "\t" << "congestion: " << (this->m_second & 0x00000011) << std::endl;
	string_stream << "\t" << "total_length: " << ntohs(this->m_total_length) << std::endl;
	string_stream << "\t" << "identification: " << ntohs(this->m_indentification) << std::endl;
	string_stream << "\t" << "flags: " << ((this->m_third & 0b1110000000000000) >> 13) << std::endl;
	string_stream << "\t" << "fragment_offset: " << (this->m_third & 0b0001111111111111) << std::endl;
	string_stream << "\t" << "time_to_live: " << ntohs(this->m_time_to_live) << std::endl;
	string_stream << "\t" << "protocol: " << (int) this->m_protocol << std::endl;
	string_stream << "\t" << "checksum: " << ntohs(this->m_checksum) << std::endl;
	string_stream << "\t" << "source: " << this->m_source.serialise_readable() << std::endl;
	string_stream << "\t" << "destination: " << this->m_destiniation.serialise_readable() << std::endl;
	string_stream << "}";

	return string_stream.str();
}

ipv4_address_t ipv4_header_t::source() const {
	return this->m_source;
}

ipv4_address_t ipv4_header_t::destination() const {
	return this->m_destiniation;
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

std::string udp_header_t::serialise_readable() const {
	std::stringstream string_stream;

	string_stream << "udp_header_t {" << std::endl;
	string_stream << "\t" << "source: " << this->source() << std::endl;
	string_stream << "\t" << "destination: " << this->destination() << std::endl;
	string_stream << "\t" << "length: " << this->length() << std::endl;
	string_stream << "\t" << "checksum: " << this->checksum() << std::endl;
	string_stream << "}";

	return string_stream.str();
}

