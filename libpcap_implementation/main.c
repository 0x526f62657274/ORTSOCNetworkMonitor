#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include "util.h"
#include "alert.h"

#define CHECK_TIME_MAX 18000
#define NUM_POLLS_MAX 1000

unsigned long bytes_captured = 0; // number of bytes captured from the interface
unsigned int polls_performed = 0; // the number of times we checked the network traffic
unsigned int rate_total = 0; // the total rate in order to calculate the average rate if traffic is saturated
unsigned int peak_rate = 0; // the highest rate found in a set of polls
time_t last_check_time = 0;
arguments args;

void packet_handler(u_char* packet_args, const struct pcap_pkthdr* header, const u_char* packet) {
    if(last_check_time == 0) { // record the current time
        last_check_time = time(0);
    }

    if(ULONG_MAX - header->len < bytes_captured) {
        //this means, somehow there was an overflow in the number of bytes captured, where it exceeded ULONG_MAX. in this case, we log this, but this should never happen. it is mainly just here as a sanity check.
        overflow_alert();
        return;
    }

    bytes_captured += header->len;

    if(last_check_time + args.check_time < time(0)) {
        int rate = bytes_captured / args.check_time;
        if(rate >= args.saturation_rate) {
            polls_performed++;
            rate_total += rate;
            if(rate > peak_rate) {
                peak_rate = rate;
            }
            if(polls_performed >= args.num_polls) {
                generate_alert(rate_total / args.num_polls, peak_rate);
                polls_performed = 0;
                rate_total = 0;
            }
            if(rate >= args.saturation_max) {
                generate_alert(peak_rate, peak_rate);
            }
        }
        else {
            polls_performed = 0; // if we didn't exceed the rate, reset the poll counter
        }
        printf("The amount of traffic captured: %lu bytes at a rate of %d per second and %d polls performed \n", bytes_captured, rate, polls_performed);
        bytes_captured = 0;
        last_check_time = time(0);
    }
}

bool parse_args(int argc, char** argv) {
    if(argc < 6) {
        printf("Listens to network traffic and reports an alert when a threshold has been reached. Usage: \n");
        printf("%s <interface> <check time in seconds> <saturation rate> <number of polls> <saturation max>\n", argv[0]);
        return false;
    }
    if(!check_interface_exists(argv[1])) {
        fprintf(stderr, "The device does not exist.\n");
        return false;
    }
    args.check_time = atoi(argv[2]);
    if(args.check_time == 0 || args.check_time > CHECK_TIME_MAX) {
        fprintf(stderr, "The check time specified is not valid.\n");
        return false;
    }
    args.saturation_rate = atoi(argv[3]);
    if(args.saturation_rate == 0) {
        fprintf(stderr, "The saturation rate specified was not valid. \n");
        return false;
    }
    args.num_polls = atoi(argv[4]);
    if(args.num_polls == 0 || args.num_polls > NUM_POLLS_MAX) {
        fprintf(stderr, "The number of polls specified was not valid.\n");
        return false;
    }
    args.saturation_max = atoi(argv[5]);
    if(args.saturation_max == 0) {
        fprintf(stderr, "The saturation max specified was not valid.\n");
        return false;
    }
    args.interface = strdup(argv[1]);
    return true;
}

int main(int argc, char** argv) {
    if(parse_args(argc, argv) == false) { // parse the user arguments
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];

    printf("Monitoring device %s\n", args.interface);
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 0, 10000, error_buffer);

    if(handle == NULL) {
        fprintf(stderr, "%s\n", error_buffer);
        return 2;
    }

    struct pcap_pkthdr header;
    const u_char* packet = pcap_next(handle, &header);
    if(packet == NULL) {
        fprintf(stderr, "Could not bind to this interface.\n");
        return 2;
    }

    pcap_loop(handle, 0, &packet_handler, NULL);

    return 0;
}
