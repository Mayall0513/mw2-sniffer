#include "MW2SA3.hpp"
#include "infpod.hpp"

#include <winhttp.h>

#include <thread>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <iostream>

std::mutex party_players_mutex;

party_t                                     party;
player_wrapper_t                            players[MAX_PLAYER_COUNT];
std::unordered_map<uint64_t, player_data_t> player_data;
std::atomic<bool>                           player_thread_continue { true };

uint32_t packed_internal_ip_address;
uint32_t packed_external_ip_address;

int main() {
    bool external_ip_success = get_external_packed_ip_address(packed_external_ip_address);
    if (false == external_ip_success) {
        std::cerr << "Could not get external IP address" << std::endl;
        return -1;
    }

    pcap_if_t * all_devices;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int find_all_result = pcap_findalldevs(&all_devices, error_buffer);
    if (-1 == find_all_result) {
        std::cerr << error_buffer << std::endl;
        return -2;
    }

    pcap_if_t * current_device = all_devices;
    uint32_t highest_index = 0;

    do {
        if (PCAP_IF_LOOPBACK == (current_device->flags & PCAP_IF_LOOPBACK) || PCAP_IF_RUNNING != (current_device->flags & PCAP_IF_RUNNING)) {
            continue;
        }

        std::cout << std::format("{:d}) {:s}", highest_index++, current_device->description) << std::endl;
    }
    while (current_device = current_device->next);

    int parsed_input_index = -1;
    std::string input;

    do {
        std::cout << "Pick a device by index: ";
        std::getline(std::cin, input);

        try {
            uint32_t potential_parsed_input_index = std::stoul(input);
            if (highest_index > potential_parsed_input_index) {
                parsed_input_index = potential_parsed_input_index;
            }
        }
        catch (std::invalid_argument) {}
    }
    while (-1 == parsed_input_index);

    pcap_if_t * selected_device = all_devices;
    for (int i = 0; i < parsed_input_index; i++) {
        selected_device = selected_device->next;
    }

    pcap_addr_t * selected_device_addresses = selected_device->addresses;
    for (; selected_device_addresses != nullptr; selected_device_addresses = selected_device_addresses->next) {
        if (AF_INET != selected_device_addresses->addr->sa_family) {
            continue;
        }

        const sockaddr_in * sock_address = reinterpret_cast<const sockaddr_in *>(selected_device_addresses->addr);
        packed_internal_ip_address = sock_address->sin_addr.s_addr;
        break;
    }

    pcap_t * device_handle = pcap_open_live(selected_device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, error_buffer);
    pcap_freealldevs(all_devices);

    if (nullptr == device_handle) {
        std::cerr << error_buffer << std::endl;
        return -3;
    }

    bpf_program filter;
    int compile_result = pcap_compile(device_handle, &filter, "udp port 28960", 1, 0);
    if (-1 == compile_result) {
        std::cerr << pcap_geterr(device_handle) << std::endl;
        return -4;
    }

    int filter_result = pcap_setfilter(device_handle, &filter);
    pcap_freecode(&filter);

    if (-1 == filter_result) {
        std::cerr << pcap_geterr(device_handle) << std::endl;
        return -5;
    }

    // set code page to match the one in MW2's English releases
    // important for Russian names in particular
    //
    // 1252 is CP1252/Windows-1252 (https://en.wikipedia.org/wiki/Windows-1252)
    SetConsoleOutputCP(1252);

    std::thread player_status_thread(update_player_statuses);
    int loop_result = pcap_loop(device_handle, 0, packet_handler, nullptr);
    player_thread_continue.store(false);

    if (0 != loop_result) {
        std::cerr << pcap_geterr(device_handle) << std::endl;
        return -6;
    }

    return 0;
}

bool get_external_packed_ip_address(uint32_t & packed_internal_ip_address) {
    HINTERNET session = WinHttpOpen(
        L"MW2SA3",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (nullptr == session) {
        return false;
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
        return false;
    }

    bool send_success = WinHttpSendRequest(
        request,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        NULL
    );

    if (false == send_success) {
        return false;
    }

    bool receive_success = WinHttpReceiveResponse(request, NULL);
    if (false == receive_success) {
        return false;
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
            else {
                return false;
            }

            delete[] read_buffer;
        }
    }
    while (0 < remaining_bytes);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    inet_pton(AF_INET, response_buffer.c_str(), &packed_internal_ip_address);
    return true;
}

void update_player_statuses() {
    system("cls");
    std::cout << "Waiting for data..." << std::endl;

    while (true == player_thread_continue.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        std::lock_guard<std::mutex> read_lock(party_players_mutex);
        if (0 == party.m_max_player_count) {
            continue;
        }

        uint64_t timestamp = epoch_timestamp_milliseconds();
        uint64_t latest_last_seen = timestamp - PLAYER_TIMEOUT_MILLISECONDS;
        bool     any_removed = false;

        for (size_t i = 0; i < MAX_PLAYER_COUNT; i++) {
            player_wrapper_t player_wrapper = players[i];
            if (false == player_wrapper.m_included) {
                continue;
            }

            player_data_t & player = player_data[player_wrapper.m_steam64_id];
            if (party.m_our_index != i && player.m_last_seen < latest_last_seen) {
                player_wrapper.m_included = false;
                player_data.erase(player_wrapper.m_steam64_id);
                any_removed = true;
            }
        }

        if (true == any_removed) {
            redraw_players();
        }
    }
}

void packet_handler(u_char * user, const struct pcap_pkthdr * headers, const uint8_t * data) {
    (VOID) (user);
    (VOID) (headers);

    const ethernet_header_t * ethernet_header = reinterpret_cast<const ethernet_header_t *>(data);
    data += sizeof(ethernet_header_t);

    const ipv4_header_t * ip_header = reinterpret_cast<const ipv4_header_t *>(data);
    const uint8_t * packet_end = data + ip_header->total_length();
    data += ip_header->header_length_bytes();

    const udp_header_t * udp_header = reinterpret_cast<const udp_header_t *>(data);
    data += sizeof(udp_header_t);

    const ptrdiff_t remaining_bytes = packet_end - data;
    packet_parser packet_parser(data, remaining_bytes);

    const bool is_outgoing = ip_header->m_source.m_packed_data == packed_internal_ip_address;

    if (true == packet_parser.has_remaining_data(4)) {
        uint32_t oob_check = packet_parser.read_bytes<uint32_t>(4);
        if (0xFFFFFFFF == oob_check) {
            std::string oob_type = packet_parser.read_string();

            if (true == std::regex_search(oob_type, partystate_regex)) {
                handle_playerstate_packet(packet_parser);
            }
            else if (true == std::regex_search(oob_type, vt_regex)) {
                // we only want to consider incoming vt packets
                if (false == is_outgoing) {
                    handle_vt_packet(ip_header, packet_parser);
                }
            }
        }
    }

    // for all other types, we only care if the packet is outgoing as we can trust our client
    // unsure if this has unintended side effects
    if (true == is_outgoing) {
        uint32_t packed_destination = ip_header->m_destiniation.m_packed_data;
        uint64_t received_timestamp = epoch_timestamp_milliseconds();

        for (int i = 0; i < MAX_PLAYER_COUNT; i++) {
            player_wrapper_t & player_wrapper = players[i];
            if (false == player_wrapper.m_included) {
                continue;
            }

            player_data_t & player = player_data[player_wrapper.m_steam64_id];
            if (player.m_ip_address.m_packed_data == packed_destination) {
                player.m_last_seen = received_timestamp;
                break;
            }
        }
    }
}

void handle_vt_packet(const ipv4_header_t * ip_header, packet_parser & packet_parser) {
    std::lock_guard<std::mutex> scope_lock(party_players_mutex);

    uint64_t received_timestamp = epoch_timestamp_milliseconds();
    packet_parser.skip_bytes(1);
    uint64_t steam64_id = packet_parser.read_bytes<uint64_t>(8);

    player_data_t & _player_data = player_data[steam64_id];

    _player_data.m_ip_address = ip_header->m_source;
    _player_data.m_ip_from_vt = true;
    _player_data.m_last_seen = received_timestamp;

    update_player_roles();
    redraw_players();
}

void handle_playerstate_packet(packet_parser & packet_parser) {
    std::lock_guard<std::mutex> scope_lock(party_players_mutex);

    uint64_t received_timestamp = epoch_timestamp_milliseconds();
    uint32_t update_tick = packet_parser.read_bytes<uint32_t>(4);

    uint8_t packet_index = packet_parser.read_bits<uint8_t>(2);
    uint8_t packet_count = packet_parser.read_bits<uint8_t>(2);

    uint8_t player_count = packet_parser.read_bytes<uint8_t>(1);
    party.m_player_count = player_count;

    if (0 == packet_index) {
        uint8_t has_string_suffix = packet_parser.read_bits<uint8_t>(1);
        packet_parser.skip_bits(2);   // unknown
        packet_parser.skip_bits(1);   // unknown

        packet_parser.skip_bytes(8);  // unknown
        packet_parser.skip_bytes(4);  // unknown
        packet_parser.skip_bytes(1);  // unknown
        packet_parser.skip_bytes(4);  // unknown
        packet_parser.skip_bytes(4);  // unknown
        uint8_t max_player_count = packet_parser.read_bytes<uint8_t>(1);
        packet_parser.skip_bytes(1);  // unknown
        packet_parser.skip_bytes(1);  // unknown
        packet_parser.skip_bits(1);   // unknown
        packet_parser.skip_bytes(8);  // unknown
        packet_parser.skip_bytes(4);  // host internal IP   (confident)
        ipv4_address_t host_external_ip = packet_parser.read_bytes<ipv4_address_t>(4);
        packet_parser.skip_bytes(2);  // host internal port (confident)
        packet_parser.skip_bytes(2);  // host external port (confident)
        packet_parser.skip_bytes(40); // left over          (confident - remainder of server data struct)
        packet_parser.skip_bytes(8);  // steam lobby id     (confident)

        if (1 == has_string_suffix) {
            // it's unclear what these strings are.
            // a sensible guess would be map names but I have not been able to capture a packet with them in
            packet_parser.read_string();
            packet_parser.read_string();
        }
        else {
            // structure is actually 11 independent bytes but just going to skip 11 since we do not know what these are anyway.
            packet_parser.skip_bytes(11);
        }

        packet_parser.skip_bytes(4); // unknown

        party.m_max_player_count = max_player_count;
        party.m_host_ip_address = host_external_ip;
    }

    while (true == packet_parser.has_remaining_data(67, 62)) {
        uint8_t index = packet_parser.read_bytes<uint8_t>(1);
        uint8_t not_included_flag = packet_parser.read_bits<uint8_t>(1);
        if (1 == not_included_flag) {
            continue;
        }

        packet_parser.skip_bits(2);   // NAT type             (confident - 3 NAT types)
        packet_parser.skip_bits(1);   // vetoed current map   (educated guess)
        packet_parser.skip_bits(1);   // invited              (unsure)
        packet_parser.skip_bits(1);   // headset present      (confident)
        packet_parser.skip_bits(18);  // voice connectivity   (confident - bit per player)
        std::string username = packet_parser.read_string();
        packet_parser.skip_bytes(4);  // clan tag             (educated guess)
        uint64_t steam64_id = packet_parser.read_bytes<uint64_t>(8);
        packet_parser.skip_bytes(4);  // player internal IP   (confident)
        ipv4_address_t external_ip = packet_parser.read_bytes<ipv4_address_t>(4);
        packet_parser.skip_bytes(2);  // player internal port (confident)
        packet_parser.skip_bytes(2);  // player external port (confident)
        packet_parser.skip_bytes(24); // left over            (confident - remainder of player data struct)
        packet_parser.skip_bytes(8);  // challenge            (unsure)
        packet_parser.skip_bits(5);   // party index          (educated guess)
        packet_parser.skip_bits(2);   // team                 (confident - 3 teams)
        packet_parser.skip_bytes(2);  // score                (confident)
        packet_parser.skip_bytes(1);  // deaths               (confident)
        packet_parser.skip_bytes(1);  // level                (confident)
        packet_parser.skip_bytes(1);  // prestige             (confident)
        packet_parser.skip_bytes(4);  // true skill           (unsure)
        packet_parser.skip_bits(10);  // icon                 (confident)
        packet_parser.skip_bits(10);  // title                (confident)
        packet_parser.skip_bits(6);   // nameplate            (unsure)
        packet_parser.skip_bits(5);   // map packs            (educated guess)

        player_data_t & _player_data = player_data[steam64_id];

        if (false == _player_data.m_ip_from_vt) {
            _player_data.m_ip_address = external_ip;
        }

        _player_data.m_username.swap(username);
        _player_data.m_last_seen = received_timestamp;

        players[index].m_included = true;
        players[index].m_steam64_id = steam64_id;
    }

    update_player_roles();
    redraw_players();
}

void redraw_players() {
    system("cls");

    std::cout << "Host IP: " << party.m_host_ip_address.to_string() << std::endl << std::endl;

    uint64_t timestamp = epoch_timestamp_milliseconds();
    uint64_t latest_last_seen = timestamp - PLAYER_TIMEOUT_MILLISECONDS;

    for (size_t i = 0; i < MAX_PLAYER_COUNT; i++) {
        player_wrapper_t & player_wrapper = players[i];
        if (false == player_wrapper.m_included) {
            continue;
        }

        player_data_t & player = player_data[player_wrapper.m_steam64_id];
        if (party.m_our_index != i && player.m_last_seen < latest_last_seen) {
            player_wrapper.m_included = false;
            player_data.erase(player_wrapper.m_steam64_id);
            continue;
        }

        std::cout << std::format("{:02d}) {:<15} {:s}", i + 1, player.m_ip_address.to_string(), player.m_username);
        if (party.m_host_index == i) {
            std::cout << " [HOST]";
        }

        if (party.m_our_index == i) {
            std::cout << " [US]";
        }

        std::cout << std::endl;
    }
}

void update_player_roles() {
    for (int i = 0; i < MAX_PLAYER_COUNT; i++) {
        player_wrapper_t & player_wrapper = players[i];
        if (false == player_wrapper.m_included) {
            continue;
        }

        player_data_t & player = player_data[player_wrapper.m_steam64_id];
        if (player.m_ip_address.m_packed_data == party.m_host_ip_address.m_packed_data) {
            party.m_host_index = i;
        }

        if (player.m_ip_address.m_packed_data == packed_external_ip_address) {
            party.m_our_index = i;
        }
    }
}