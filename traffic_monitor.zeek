export {
     redef enum Notice::Type += {
          ORTSOC_Traffic_Alert
     };
}


global traffic_measured: int = 0;
global last_check_time: time;
global polls_performed: int = 0;
global polling_total: int = 0;

const measurement_interval: interval = 5sec;
const measurement_interval_seconds: int = 5; ## this variable exists because of the way time arithmetic works in zeek scripting ... 
const polls: int = 5; ## the number of polls before taking the average to check the traffic
const average_max = 30000; ## this is measured in bytes, and represents the amount at which point an alert will be created if the traffic over the number oof polls exceeds this amount
const absolute_max = 125000; ## also measured in bytes, and if any polls exceed this amount of traffic, an alert will generate

function generate_alert(a: string) {
    print a;
    NOTICE([$note=ORTSOC_Traffic_Alert, $msg=fmt("The sensor is using too much traffic: %s", a)]);
}

event raw_packet(p: raw_pkt_hdr) {
   traffic_measured += p$l2$len;
   if(last_check_time + measurement_interval < current_time()) {
       local rate: int = traffic_measured / measurement_interval_seconds;
       print fmt("Traffic measured on this interval, %s bytes per second", rate);
       polls_performed += 1;
       polling_total += rate;
       if(polls_performed >= polls) {
            if(polling_total / polls >= average_max) {
		generate_alert(fmt("average rate exceed the average rate maximum. rate calculated: %s", polling_total / polls));
	        polls_performed = 0;
		polling_total = 0;
	    }
       }
       if(rate >= absolute_max) {
          generate_alert(fmt("measured rate exceeded the absolute maximum for a single poll. rate: %s", rate));
       }
       traffic_measured = 0;
       last_check_time = current_time();
   }
}

event zeek_init() {
	last_check_time = current_time();
	print fmt("Starting network traffic monitor...");
}


