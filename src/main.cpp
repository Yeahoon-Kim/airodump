#include "airodump.hpp"

#include <csignal>

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
