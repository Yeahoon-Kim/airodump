#pragma once

#include <iostream>
#include <unordered_map>
#include <iomanip>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <tuple>
#include <pcap.h>

#include "radiotap.hpp"

extern std::mutex mutexer;
extern std::atomic<bool> isEnd(false); 

std::tuple<uint32_t, std::string> parsingTags(const char* payload, const int payloadLength);

void printScreen(const std::unordered_map<Mac, std::pair<uint32_t, std::tuple<uint32_t, std::string>>>& m);

bool airodump(pcap_t* pcap);
