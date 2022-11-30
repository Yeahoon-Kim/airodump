#pragma once

#include <iostream>
#include "mac.hpp"

struct ieee80211_radiotap_header {
    uint8_t it_version;     // radiotap version, always 0
    uint8_t it_pad;         // padding (or alignment)
    uint16_t it_len;        // overall radiotap header length
    uint32_t it_present;    // (first) present word;
} __attribute__((__packed__));

typedef struct beacon_frame {
    uint8_t version:2;
    enum {
        MANAGEMENT_FRAMES       = 0,    // 802.11 Management Frames
        CONTROL_FRAMES          = 1,    // 802.11 Control Frames
        DATA_FRAMES             = 2     // 802.11 Data Frames
    } type:2;
    enum {
        // In case of 802.11 Management Frames
        Association_request     = 0,
        Association_response    = 1,
        Reassociation_request   = 2,
        Reassociation_response  = 3,
        Probe_request           = 4,
        Probe_response          = 5,
        Timing_Advertisemant    = 6,
        Beacon                  = 8,
        ATIM                    = 9,
        Disassociation          = 10,
        Authentication          = 11,
        Deauthentication        = 12,
        Action                  = 13,
        Action_no_ack           = 14,

        // In case of 802.11 Control Frames
        Beamforming_report_poll = 4,
        VHT_NDP_Announcement    = 5,
        Control_wrapper         = 7,
        Block_ACK_request       = 8,
        Block_ACK               = 9,
        PS_Poll                 = 10,
        Ready_To_Send           = 11,
        Clear_To_Send           = 12,
        ACK                     = 13,
        CF_End                  = 14,
        CF_End_CF_Ack           = 15,

        // In case of 802.11 Data Frames
        Data                    = 0,
        Data_CF_Ack             = 1,
        Data_CF_Poll            = 2,
        Data_CF_Ack_CF_Poll     = 3,
        Null                    = 4,
        CF_Ack                  = 5,
        CF_Poll                 = 6,
        CF_Ack_CF_Poll          = 7,
        QoS_Data                = 8,
        QoS_Data_CF_Ack         = 9,
        QoS_Data_CF_Poll        = 10,
        QoS_Data_CF_Ack_CF_Poll = 11,
        QoS_Null                = 12,
        QoS_CF_Poll             = 14,
        QoS_CF_Ack_CF_Poll      = 15
    } subtype:4;
    uint8_t flags;
    uint16_t duration;
    Mac destMAC;
    Mac srcMAC;
    Mac BSSID;
    uint16_t fragNum:4, seqNum:12;
} __attribute__((__packed__));

struct fixed_param {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_information;
} __attribute__((__packed__));

typedef struct fixed_manage_frame* PFixedManageFrame;
typedef struct ieee80211_radiotap_header* PRadiotapHdr;
typedef struct beacon_frame* PBeacon;
