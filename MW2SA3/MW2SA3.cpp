#include "MW2SA3.hpp"
#include "infpod.hpp"

#include <memory>
#include <span>
#include <chrono>
#include <thread>
#include <conio.h>
#include <algorithm>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

using namespace std::chrono_literals;

party_t  party;
player_t players[MAX_PLAYER_COUNT];

uint32_t packed_internal_ip_address;
uint32_t packed_external_ip_address = get_external_packed_ip_address();

uint32_t get_external_packed_ip_address() {
    HINTERNET session = WinHttpOpen(
        L"MW2SA3",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (nullptr == session) {
        return 0;
    }

    HINTERNET connection = WinHttpConnect(
        session,
        L"checkip.amazonaws.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        0
    );

    if (nullptr == connection) {
        WinHttpCloseHandle(session);
        return 0;
    }

    // Create request
    HINTERNET request = WinHttpOpenRequest(
        connection,
        L"GET",
        L"/",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (nullptr == request) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 0;
    }

    bool send_success = WinHttpSendRequest(
        request,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (false == send_success) {
        return 0;
    }

    bool receive_success = WinHttpReceiveResponse(request, NULL);
    if (false == receive_success) {
        return 0;
    }

    std::string response_buffer {};
    unsigned long remaining_bytes;

    do {
        remaining_bytes = 0;
        bool bytes_available_success = WinHttpQueryDataAvailable(request, &remaining_bytes);

        if (true == bytes_available_success && 0 < remaining_bytes) {
            char * read_buffer = new char[remaining_bytes + 1];

            unsigned long bytes_read = 0;
            bool read_success = WinHttpReadData(
                request,
                read_buffer,
                remaining_bytes,
                &bytes_read
            );

            if (true == read_success) {
                read_buffer[bytes_read] = 0;
                response_buffer.append(read_buffer);
            }

            delete[] read_buffer;
        }
    }
    while (0 < remaining_bytes);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    uint32_t value = 0;
    inet_pton(AF_INET, response_buffer.c_str(), &value);
    return value;
}

int main() {
    pcap_if_t * all_devices;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (-1 == pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &all_devices, error_buffer) || nullptr == all_devices) {
        std::cout << error_buffer << std::endl;
        return -1;
    }

    pcap_if_t * current_device = all_devices;
    int highest_index = 0;

    do {
        if (PCAP_IF_LOOPBACK == (current_device->flags & PCAP_IF_LOOPBACK) || PCAP_IF_RUNNING != (current_device->flags & PCAP_IF_RUNNING)) {
            continue;
        }

        std::cout << "(" << highest_index++ << ") " << current_device->description << std::endl;
    }
    while (current_device = current_device->next);

    int parsed_input_index = 0;
    std::string input;

    do {
        std::cout << "Pick a device by index: ";
        std::cin >> input;

        try {
            int potential_parsed_input_index = std::stoi(input);
            if (highest_index > potential_parsed_input_index) {
                parsed_input_index = potential_parsed_input_index;
            }
        }
        catch (std::invalid_argument) {  }
    }
    while (-1 == parsed_input_index);

    pcap_if_t * selected_device = all_devices;
    for (int i = 0; i < parsed_input_index; i++) {
        selected_device = selected_device->next;
    }
    
    pcap_addr_t * selected_device_addresses = selected_device->addresses;
    for (; selected_device_addresses != nullptr;  selected_device_addresses = selected_device_addresses->next) {
        if (AF_INET != selected_device_addresses->addr->sa_family) {
            continue;
        }
        
        const sockaddr_in * sock_address = reinterpret_cast<const sockaddr_in *>(selected_device_addresses->addr);
        packed_internal_ip_address = sock_address->sin_addr.s_addr;
        break;
    }

    pcap_t * device_handle = pcap_open(selected_device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, error_buffer);
    pcap_freealldevs(all_devices);

    bpf_program filter;
    pcap_compile(device_handle, &filter, "ip and udp", 1, 0);
    pcap_setfilter(device_handle, &filter);

    if (nullptr == device_handle) {
        std::cout << error_buffer << std::endl;
        return -1;
    }

    std::thread player_status_thread(update_player_statuses);
    pcap_loop(device_handle, 0, packet_handler, nullptr);
    return 0;
}

void update_player_statuses() {
    while (true) {
        std::this_thread::sleep_for(1000ms);

        system("cls");
        if (0 == party.m_max_player_count) {
            continue;
        }

        std::cout << "Host IP: " << party.m_host_ip_address.serialise_readable() << std::endl << std::endl;

        uint64_t timestamp = epoch_timestamp_milliseconds();
        uint64_t latest_last_seen = timestamp - PLAYER_TIMEOUT_MILLISECONDS;

        for (int i = 0; i < MAX_PLAYER_COUNT; i++) {
            player_t& player = players[i];
            if (false == player.m_included) {
                continue;
            }

            if (party.m_our_index != i && player.m_last_seen < latest_last_seen) {
                player.m_included = false;
                continue;
            }

            std::cout << i << ") " << player.m_username << " " << player.m_ip_address.serialise_readable() << " " << (PLAYER_TIMEOUT_MILLISECONDS - (timestamp - player.m_last_seen));
            if (party.m_host_index == i) {
                std::cout << " [HOST]";
            }

            if (party.m_our_index == i) {
                std::cout << " [US]";
            }

            std::cout << std::endl;
        }
    }
}

void packet_handler(u_char * user, const struct pcap_pkthdr * headers, const u_char * data) {
    (VOID) (user);

    const char * cursor = reinterpret_cast<const char *>(data);

    const ethernet_header_t * ethernet_header = std::launder(reinterpret_cast<const ethernet_header_t *>(cursor));
    cursor += sizeof(ethernet_header_t);

    const ipv4_header_t * ip_header = std::launder(reinterpret_cast<const ipv4_header_t *>(cursor));
    cursor += ip_header->header_length_bytes();

    const udp_header_t * udp_header = std::launder(reinterpret_cast<const udp_header_t *>(cursor));
    cursor += sizeof(udp_header_t);

    if (28960 != udp_header->source() && 28960 != udp_header->destination()) {
        return;
    }

    const size_t network_header_bytes = sizeof(ethernet_header_t) + ip_header->header_length_bytes() + sizeof(udp_header_t);
    const size_t remaining_bytes = ip_header->total_length() - network_header_bytes;
    packet_parser packet_parser(reinterpret_cast<const uint8_t *>(data + network_header_bytes), remaining_bytes);

    uint32_t oob_check = packet_parser.read_uint32();
    if (0xFFFFFFFF == oob_check) {
        std::string oob_type = packet_parser.read_string();

        if (true == std::regex_search(oob_type, partystate_regex)) {
            handle_playerstate_packet(packet_parser);
        }
    }

    // for all other types, we only care if the packet is outgoing as we can trust our client
    // unsure if this has unintended side effects
    if (ip_header->source().packed_int32() == packed_internal_ip_address) {
        uint32_t packed_destination = ip_header->destination().packed_int32();

        for (int i = 0; i < MAX_PLAYER_COUNT; i++) {
            player_t& player = players[i];
            if (false == player.m_included) {
                continue;
            }

            if (player.m_ip_address.packed_int32() == packed_destination) {
                player.m_last_seen = epoch_timestamp_milliseconds();
                break;
            }
        }
    }
}

void handle_playerstate_packet(packet_parser & packet_parser) {
    uint64_t received_timestamp = epoch_timestamp_milliseconds();
    uint32_t update_tick = packet_parser.read_uint32();
    uint8_t  update_type = packet_parser.read_uint8();
    uint8_t  player_count = packet_parser.read_uint8();

    party.m_player_count = player_count;

    // If the least significant bit is set, party information is stored as well as players
    if (0 == (update_type & 1)) {
        packet_parser.skip_bytes(8);
        packet_parser.read_uint32();
        packet_parser.read_uint8();
        packet_parser.read_uint32();
        packet_parser.read_uint32();
        uint8_t max_player_count = packet_parser.read_uint8();
        packet_parser.read_uint8();
        packet_parser.read_uint8();
        packet_parser.read_bit();
        packet_parser.skip_bytes(8);
        ipv4_address_t host_internal_ip = packet_parser.read_ipv4_address();
        ipv4_address_t host_external_ip = packet_parser.read_ipv4_address();
        uint16_t host_internal_port = packet_parser.read_uint16();
        uint16_t host_external_port = packet_parser.read_uint16();
        packet_parser.skip_bytes(40);
        uint64_t steam_lobby_id = packet_parser.read_uint64();
        packet_parser.read_uint8();
        packet_parser.skip_bytes(8);
        packet_parser.read_uint8();
        packet_parser.read_uint8();
        packet_parser.read_uint32();

        party.m_max_player_count  = max_player_count;
        party.m_host_ip_address = host_external_ip;
    }

    while (true == packet_parser.has_remaining_data(42)) {
        // sanity check
        uint8_t player_index = packet_parser.read_uint8();
        if (player_index >= MAX_PLAYER_COUNT) {
            continue;
        }

        bool not_included = packet_parser.read_bit();
        if (true == not_included) {
            continue;
        }

        uint8_t nat_type = packet_parser.read_bits_as_uint8(2);
        bool veteod_map = packet_parser.read_bit();
        bool invited = packet_parser.read_bit();
        bool headset_present = packet_parser.read_bit();
        uint32_t voice_connectivity = packet_parser.read_bits_as_uint32(18);
        std::string username = packet_parser.read_string();
        packet_parser.skip_bytes(4);
        uint64_t player_steam64_id = packet_parser.read_uint64();
        ipv4_address_t player_internal_ip = packet_parser.read_ipv4_address();
        ipv4_address_t player_external_ip = packet_parser.read_ipv4_address();
        uint16_t player_internal_port = packet_parser.read_uint16();
        uint16_t player_external_port = packet_parser.read_uint16();
        packet_parser.skip_bytes(24);
        uint64_t challenge = packet_parser.read_uint64();
        uint8_t sub_party_index = packet_parser.read_bits_as_uint8(5);
        uint8_t team = packet_parser.read_bits_as_uint8(2);
        uint16_t score = packet_parser.read_uint16();
        uint8_t deaths = packet_parser.read_uint8();
        uint8_t level = packet_parser.read_uint8() + 1; // levels are offset by 1 since a player cannot be level 0
        uint8_t prestige = packet_parser.read_uint8();
        uint32_t true_skill = packet_parser.read_uint32();
        uint16_t icon = packet_parser.read_bits_as_uint16(10);
        uint16_t title = packet_parser.read_bits_as_uint16(10);
        uint16_t nameplate = packet_parser.read_bits_as_uint8(6);
        uint8_t map_packs = packet_parser.read_bits_as_uint8(5);

        players[player_index].m_included   = true;
        players[player_index].m_index      = player_index;
        players[player_index].m_username   = username;
        players[player_index].m_steam64_id = player_steam64_id;  // TODO: We can not trust this data since people can spoof it. I'm not sure if this data can be found anywhere else or if it's even necessary to record
        players[player_index].m_ip_address = player_external_ip; // TODO: We can not trust this data since people can spoof it. We should instead rely on the source IP (IE in IP header - unspoofable) of the vt (?) packet sent when a player first connects
        players[player_index].m_last_seen  = received_timestamp;
    }

    for (int i = 0; i < min(MAX_PLAYER_COUNT, party.m_player_count); i++) {
        player_t& player = players[i];
        if (false == player.m_included) {
            continue;
        }

        if (player.m_ip_address.packed_int32() == party.m_host_ip_address.packed_int32()) {
            party.m_host_index = i;
        }

        if (player.m_ip_address.packed_int32() == packed_external_ip_address) {
            party.m_our_index = i;
        }
    }
}