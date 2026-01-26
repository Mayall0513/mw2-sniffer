#include "packet_parser.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <chrono>
#include <regex>

#include <pcap.h>
#include <winsock2.h>
#include <tchar.h>

// the max player count is hardcoded to 18 in the MW2 binary, we're safe to make that same assumption
const int MAX_PLAYER_COUNT = 18;

// this timeout seems much too long, it's unclear how the game keeps track of when a player leaves
const int PLAYER_TIMEOUT_MILLISECONDS = 720000;

std::regex partystate_regex("^\\d+partystate$");

uint32_t get_external_packed_ip_address();

void update_player_statuses();
void packet_handler(u_char * user, const struct pcap_pkthdr * headers, const u_char * data);
void handle_playerstate_packet(packet_parser & packet_parser);

inline uint64_t epoch_timestamp_milliseconds() { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }

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
	std::string    m_username;
	uint64_t       m_steam64_id;
	ipv4_address_t m_ip_address;
	uint64_t       m_last_seen;
};