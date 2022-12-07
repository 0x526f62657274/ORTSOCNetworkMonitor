#include "util.h"

bool check_interface_exists(char* interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    pcap_if_t* to_free;

    if(pcap_findalldevs(&devices, errbuf) == 0) {
        to_free = devices;
        while(devices != NULL) {
            if(strcmp(interface, devices->name) == 0) {
                pcap_freealldevs(to_free);
                return true;
            }
            devices = devices->next;
        }
        pcap_freealldevs(to_free);
    }
    else {
        fprintf(stderr, "%s\n", errbuf);
    }
    return false;
}