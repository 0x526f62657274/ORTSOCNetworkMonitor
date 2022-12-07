#include <stdio.h>
#include <pcap.h>
#include "util.h"

int main(int argc, char** argv) {
    char error_buffer[PCAP_ERRBUF_SIZE];

    if(argc < 2) {
        printf("Listens to network traffic and reports an alert when a threshold has been reached. Usage: \n");
        printf("%s -i <interface>\n", argv[0]);
        return 1;
    }

    if(!check_interface_exists(argv[1])) {
        fprintf(stderr, "The device does not exist.\n");
    }

    printf("Looking at device %s\n", argv[1]);
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 10000, error_buffer);

    struct pcap_pkthdr header;
    const u_char* packet = pcap_next(handle, &header);
    if(packet == NULL) {
        fprintf(stderr, "Could not bind to this interface.\n");
        return 2;
    }

    return 0;
}
