#include <iostream>
#include <csignal>
#include <unordered_map>
#include <tuple>
#include <pcap.h>

#include "radiotap.hpp"

void interruptHandler(const int signo) {




}

using namespace std;

enum ENC {
    OPN, WEP, WPA, WPA2, WPA3
};

enum CIPHER {
    CCMP, 
};

// unordered_map<Mac, tuple<int, int, int, int, int, int, int, int, int, >>

int manageTag(u_char* packet, int idx) {
    switch(packet[idx]) {
    case 0:     // SSID parameter set
    case 1:     // Supported Rates
    case 3:     // DS Parameter set
    case 5:     // Traffic Indication Map(TIM)
    case 42:    // ERP Information
    case 48:    // RSN Information
    case 50:    // Extended Supported Rates
    case 45:    // HT Capabilities
    case 61:    // HT Information
    case 127:   // Extended Capabilities
    case 221:   // Vender Specific
    default:
    }
}

std::string findESSID(char* payload) {
    if(payload[0] != 0) return NULL;
    return std::string(payload + 2, payload[1]);
}

bool parsingTags(const char* payload, const int payloadLength) {
    std::string ESSID;
    int channel;

    while( true ) {

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
    
    int res, flag;

    while( true ) {
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
        radioHdrLength = pRadioTapHeader->it_len;
        pBeaconFrame = (PBeacon)(packet + radioHdrLength);

        // Check if the frame is Beacon
        if(pBeaconFrame->type != beacon_frame::MANAGEMENT_FRAMES) continue;
        if(pBeaconFrame->subtype != beacon_frame::Beacon) continue;

        // Cast fixed parameters and tagged parameters
        pFixedManageFrame = (PFixedManageFrame)(((uint8_t*)pBeaconFrame) + sizeof(struct beacon_frame));
        taggedParameter = (char*)pFixedManageFrame + sizeof(struct fixed_param);

        BSSID = pBeaconFrame->BSSID;
        tagLength = packetLength - radioHdrLength - sizeof(struct beacon_frame) - sizeof(struct fixed_param);


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

    // airodump(dev);

    pcap_close(pcap);
}
