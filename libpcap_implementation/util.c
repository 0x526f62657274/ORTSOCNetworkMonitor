//
// Created by Robert on 11/14/22.
//
#include "util.h"

bool check_interface_exists(char* interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;

    if(pcap_findalldevs(&devices, errbuf) == 0) {
        printf("Searching\n");
        struct pcap_if* device;
        while(devices->next != NULL) {
            device = devices->next;
            if(strcmp(interface, device->name) == 0) {
                return true;
            }
        }
    }
    return false;
}