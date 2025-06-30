#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>


struct PairHasher {
    std::size_t operator()(const std::pair<std::string, std::string>& p) const {
        return std::hash<std::string>{}(p.first) ^
            (std::hash<std::string>{}(p.second) << 1);
    }
};

int main(int argc, char** argv) {

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file" << std::endl;
        return 1;
    }

    std::unordered_map<std::pair<std::string, std::string>,
        uint32_t, 
        PairHasher> ip_pair_counts;

    int packets_count = 0;
    int ipv4_count = 0;

    while (true) {

        uint16_t packet_length;
        size_t packet_skip_size = 14; //Ethernet header size

        //Packet size read
        file.read(reinterpret_cast<char*>(&packet_length), sizeof(packet_length));
        if (file.gcount() != sizeof(packet_length)) {
            break;
        }

        if (packet_length == 0) {
            continue;
        }

        // Ethernet header read
        char ethernet_header[14];
        file.read(ethernet_header, sizeof(ethernet_header));
        if (file.gcount() != sizeof(ethernet_header)) {
            break;
        }

        // IPv4 check
        if (static_cast<uint8_t>(ethernet_header[12]) == 0x08 && static_cast<uint8_t>(ethernet_header[13]) == 0x00) {

            ipv4_count++;

            char ip_header[20];
            file.read(ip_header, sizeof(ip_header));

            uint8_t src_ip[4], dst_ip[4];

            for (int i = 0; i < 4; i++) {
                src_ip[i] = static_cast<uint8_t>(ip_header[12 + i]);
                dst_ip[i] = static_cast<uint8_t>(ip_header[16 + i]);
            }

            char src_str[16], dst_str[16];
            snprintf(src_str, sizeof(src_str), "%d.%d.%d.%d", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
            snprintf(dst_str, sizeof(dst_str), "%d.%d.%d.%d", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
            auto ip_pair = std::make_pair(std::string(src_str), std::string(dst_str));

            ip_pair_counts[ip_pair]++;

            packet_skip_size = 34; //IPV4 header size
        }
        file.seekg(packet_length - packet_skip_size, std::ios::cur);
        packets_count++;
    }

    // Print statistic
    std::cout << "Packets processed:\t" << packets_count << std::endl;
    std::cout << "Packets contains IPv4:\t" << ipv4_count << std::endl;
    std::cout << "Packets without IPv4:\t" << packets_count - ipv4_count << std::endl << std::endl;

    // Sorting
    std::vector<const std::pair<const std::pair<std::string, std::string>, uint32_t>*> sorted_ips_p;
    sorted_ips_p.reserve(ip_pair_counts.size());

    for (const auto& pair : ip_pair_counts) {
        sorted_ips_p.push_back(&pair);
    }
    std::sort(sorted_ips_p.begin(), sorted_ips_p.end(),
        [](const auto a, const auto b) {
            return a->second > b->second;
        });

    // Print IP's
    for (const auto ptr : sorted_ips_p) {
        std::cout << std::left
            << std::setw(17) << (ptr->first.first + " ")
            << "-> "
            << std::setw(17) << (ptr->first.second + " ")
            << std::right << std::setw(6) << ptr->second << '\n';
    }

    return 0;
}