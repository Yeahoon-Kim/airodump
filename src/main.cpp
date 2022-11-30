#include <iostream>
#include <csignal>
#include <unordered_map>
#include <iomanip>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <tuple>
#include <pcap.h>

#include "radiotap.hpp"

void interruptHandler(const int signo) {
    switch(signo) {
        case SIGINT:
            std::cout << "Keyboard Interrupt\n";
            break;
        case SIGTERM:
            std::cout << "Terminate signal\n";
            break;
        default: break;
    }

    isEnd.store(true);
}

using namespace std;
std::mutex mutexer;
std::atomic<bool> isEnd(false); 

std::tuple<uint32_t, std::string> parsingTags(const char* payload, const int payloadLength) {
    int channel, currentIdx = 0, tagLength;
    char const* reader = payload;

    std::string ESSID;

    // Find SSID
    tagLength = reader[1];
    ESSID = std::string(reader + 2, tagLength);
    currentIdx += (2 + tagLength);

    while( currentIdx < payloadLength ) {
        tagLength = reader[1];

        switch(reader[0]) {
            case 1:     // Supported Rates
                break;
            case 3:     // DS Parameter set
                channel = reader[2];
                break;
            case 5:     // Traffic Indication Map(TIM)
            case 42:    // ERP Information
            case 48:    // RSN Information
            case 50:    // Extended Supported Rates
            case 45:    // HT Capabilities
            case 61:    // HT Information
            case 127:   // Extended Capabilities
            case 221:   // Vender Specific

            default: break;
        }

        reader += tagLength + 2;
        currentIdx += tagLength + 2;
    }

    return std::tuple<uint32_t, std::string>(channel, ESSID);
}

void printScreen(const unordered_map<Mac, std::pair<uint32_t, std::tuple<uint32_t, std::string>>>& m) {
    using namespace std::chrono_literals;
    
    while(not isEnd.load()) {
        cout << "\033[2J\033[1;1H"; // Clear screen
        cout << "\nBSSID              PWR   Beacons  ESSID\n";

        [m]() {
            std::lock_guard<std::mutex> locker(mutexer);

            for(const auto& line: m) {
                std::cout << (std::string)line.first << "  ";
                std::cout << std::setw(4) << line.second.first << "  "; 
                std::cout << std::setw(7) << std::get<0>(line.second.second) << "  ";
                std::cout << std::get<1>(line.second.second) << '\n';
            }
        }();

        std::this_thread::sleep_for(100ms);
    }
}

bool airodump(const char* dev, pcap_t* pcap) {
    PFixedManageFrame pFixedManageFrame;
    PRadiotapHdr pRadioTapHeader;
    PBeacon pBeaconFrame;

    struct pcap_pkthdr* header;
    u_char* packet;

    uint16_t radioHdrLength;
    uint32_t packetLength, tagLength;
    Mac BSSID;
    
    char* taggedParameter;
    std::tuple<uint32_t, std::string> contents;
    unordered_map<Mac, std::pair<uint32_t, std::tuple<uint32_t, std::string>>> DB;
    
    int res, flag;

    std::thread printer = std::thread(printScreen, DB);
    printer.detach();

    while(not isEnd.load()) {
        res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
		// PCAP_ERROR : When interface is down
		if (res == PCAP_ERROR or res == PCAP_ERROR_BREAK) {
			cout << "Error : Error while pcap_next_ex: ";
			cout << pcap_geterr(pcap) << endl;

			break;
		}

        // Check total packet length
        packetLength = header->len;

        // Cast radiotap header
        pRadioTapHeader = (PRadiotapHdr)packet;

        // Cast beacon frame header
        radioHdrLength = ntohs(pRadioTapHeader->it_len);
        pBeaconFrame = (PBeacon)(packet + radioHdrLength);

        // Check if the frame is Beacon
        if(pBeaconFrame->type != beacon_frame::MANAGEMENT_FRAMES) continue;
        if(pBeaconFrame->subtype != beacon_frame::Beacon) continue;

        // Cast fixed parameters and tagged parameters
        pFixedManageFrame = (PFixedManageFrame)(((uint8_t*)pBeaconFrame) + sizeof(struct beacon_frame));
        taggedParameter = (char*)pFixedManageFrame + sizeof(struct fixed_param);

        BSSID = pBeaconFrame->BSSID;
        tagLength = packetLength - radioHdrLength - sizeof(struct beacon_frame) - sizeof(struct fixed_param);

        auto it = DB.find(BSSID);
        if(it != DB.end()) it->second.first++;
        else {
            contents = parsingTags(taggedParameter, tagLength);
            [BSSID, contents](unordered_map<Mac, std::pair<uint32_t, std::tuple<uint32_t, std::string>>> DB) {
                std::lock_guard<std::mutex> locker(mutexer);
                DB[BSSID] = {0, contents};
            }(DB);
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, interruptHandler);
    signal(SIGTERM, interruptHandler);

    if(argc != 2) {
        cerr << "Error: Wrong parameters are given\n";
        cerr << "syntax : airodump <interface>\n";
        cerr << "sample : airodump mon0" << endl;

        return 1;
    }

    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap;

    dev = argv[1];
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if(pcap == NULL) {
        cerr << "Error: Error while open device ";
        cerr << errbuf << endl;

        return 1;
    }

    airodump(dev, pcap);

    pcap_close(pcap);
}
