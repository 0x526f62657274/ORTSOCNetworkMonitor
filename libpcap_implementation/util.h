#pragma once
#include <stdbool.h>
#include <pcap.h>
#include <string.h>

typedef struct arguments arguments;

struct arguments {
    char* interface; // the interface we want to bind to...
    int check_time; // the length of time before checking traffic
    int num_polls; // how many traffic polls to do before concluding that the network is too saturated
    int saturation_rate; // the rate to consider the network saturated, measured in bytes
    int saturation_max; // generate an alert if traffic is above this maximum, regardless of previous polls
};

bool check_interface_exists(char* interface);
