#include "packet_parser.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <chrono>
#include <regex>

#include <pcap.h>
#include <winsock2.h>
#include <tchar.h>

// The max player count is hardcoded to 18 in MW2, we're safe to set that same constraint
const int MAX_PLAYER_COUNT = 18;

// This timeout seems much too long, it's unclear how the game keeps track of when a player leaves
const int PLAYER_TIMEOUT_MILLISECONDS = 720000;

struct party_t {
	uint8_t        m_max_player_count;
	uint8_t        m_player_count;
	ipv4_address_t m_host_ip_address;
	uint8_t        m_our_index;
	uint8_t        m_host_index;
};

struct player_t {
	bool           m_included;
	uint8_t        m_index;
	std::string    m_username { "no_name" };
	uint64_t       m_last_seen;
	uint64_t       m_steam64_id;
	ipv4_address_t m_ip_address;
	bool           m_vt;
};

std::regex partystate_regex("^\\d+partystate$");
std::regex vt_regex("^vt$");

uint32_t get_external_packed_ip_address();

void update_player_statuses();
void packet_handler(u_char * user, const struct pcap_pkthdr * headers, const u_char * data);

void handle_playerstate_packet(packet_parser & packet_parser);
void handle_vt_packet(const ipv4_header_t * ip_header, packet_parser & packet_parser);

void add_or_update_player(uint64_t steam64_id, player_t ** player);

inline uint64_t epoch_timestamp_milliseconds() { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }

