# ORTSOCNetworkMonitor

## Purpose

This idea originally came about when it was determined that the amount of traffic a sensor might send would saturate the bandwidth on some of the more rural clients. This tool allows for monitoring of how much traffic is being sent, so that it can be monitored in case it is too high.

## Technical Info

This network monitor is a Zeek script to measure the amount of traffic on the wire, and it can output a notice to the `notice.log` file if it is considered to be saturated. There are several options that can be configured in this script, based on what is needed:

`measurement_interval`: how long, in seconds, to conduct measurements of the traffic

`measurement_interval_seconds`: an int representation of `measurement_interval`, because of the way Zeek scripting works.

`polls`: the number of times the amount of traffic on the network will be pulled, before averaging.

`average_max`: the highest acceptable average.

`absolute_max`: the highest acceptable amount of traffic in a single poll.


The script binds to the raw_packet event. This may be slow, depending on the amount of traffic, however that was not tested in this project. It is intended to be used on a sensor, or other hardware where the traffic going from a sensor can be measured. To run the script: `zeek -C -i ens160 traffic_monitor.zeek`, where ens160 is the interface you would like to listen to.
