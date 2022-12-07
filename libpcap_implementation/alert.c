#include <stdio.h>
#include "alert.h"

void generate_alert(unsigned int rate_detected, unsigned int peak_rate) {
    FILE* f;
    f = fopen("network_logs.log", "ab+");
    if(f != NULL) {
        fprintf(f, "time: %ld | network traffic alert, with average rate of %d and peak of %d\n", time(0), rate_detected, peak_rate);
    }
    else {
        fprintf(stderr, "Could not write to the file network_logs.log\n");
    }
    printf("Alert generated with an average rate of %d and peak of %d\n", rate_detected, peak_rate);
    fclose(f);
}

void overflow_alert() {
    FILE* f;
    f = fopen("network_logs.log", "ab+");
    if(f != NULL) {
        fprintf(f, "time: %ld | Byte measurement counter overflowed. The number of bytes detected exceed the ULONG_MAX.\n", time(0));
    }
    else {
        fprintf(stderr, "Could not write to the file network_logs.log\n");
    }
    fprintf(stderr, "ERROR: Byte measurement counter overflowed. The number of bytes detected exceed the ULONG_MAX.\n");
    fclose(f);
}