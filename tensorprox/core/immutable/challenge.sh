#!/bin/bash

# Ensure jq is installed
if ! command -v jq &> /dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y jq -qq
fi

machine_name="$1"
challenge_duration="$2"
label_hashes="$3"
playlist_json=$(echo "$4" | jq '.' 2>/dev/null)
king_ip="$5"
traffic_gen_path="$6"

# Build grep patterns for counting occurrences of each label
benign_pattern=$(echo "$label_hashes" | jq -r '.BENIGN | join("\\|")')
udp_flood_pattern=$(echo "$label_hashes" | jq -r '.UDP_FLOOD | join("\\|")')
tcp_syn_flood_pattern=$(echo "$label_hashes" | jq -r '.TCP_SYN_FLOOD | join("\\|")')

# Define the traffic filtering based on machine_name
if [ "$machine_name" == "king" ]; then
    filter_traffic="(tcp or udp) and inbound"
else
    filter_traffic="(tcp or udp) and outbound"
fi


# Traffic generation for attacker and benign
if [[ "$machine_name" == "attacker" || "$machine_name" == "benign" ]]; then

    # Install Python3 and pip if not installed
    if ! command -v python3 &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip
    fi

    # Install necessary Python packages
    for package in faker scapy pycryptodome; do
        if ! python3 -c "import $package" &>/dev/null; then
            sudo pip3 install $package > /dev/null 2>&1
        fi
    done

    # Dump playlist into temporary json file
    echo "$playlist_json" > /tmp/playlist.json

    # Start traffic generator with the playlist
    nohup python3 $traffic_gen_path --playlist /tmp/playlist.json --receiver-ips $king_ip --interface ipip-$machine_name > /tmp/traffic_generator.log 2>&1 &

fi

# Ensure tcpdump is installed
if ! command -v tcpdump &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y tcpdump
fi

# Capture network traffic for a duration
sudo timeout $challenge_duration tcpdump -i ipip-$machine_name -w /tmp/capture.pcap "$filter_traffic"

# Extract the payload data from pcap file and count occurrences
sudo tcpdump -nn -r /tmp/capture.pcap -A | grep -o "$benign_pattern\\|$udp_flood_pattern\\|$tcp_syn_flood_pattern" > /tmp/traffic_data.txt

# Count occurrences of each label
benign_count=$(grep -o -E "$benign_pattern" /tmp/traffic_data.txt | wc -l)
udp_flood_count=$(grep -o -E "$udp_flood_pattern" /tmp/traffic_data.txt | wc -l)
tcp_syn_flood_count=$(grep -o -E "$tcp_syn_flood_pattern" /tmp/traffic_data.txt | wc -l)

# Measure RTT if the machine is attacker or benign
if [[ "$machine_name" == "attacker" || "$machine_name" == "benign" ]]; then

    # Execute RTT measurement command
    ping -c 4 $king_ip > /tmp/rtt.txt

    # Extract average RTT from the ping output (assuming the ping command ran successfully)
    rtt_avg=$(grep -oP 'rtt min/avg/max/mdev = \d+\.\d+/(\d+\.\d+)' /tmp/rtt.txt | awk -F'/' '{print $5}')

    # Output the counts along with the average RTT
    echo "BENIGN:$benign_count, UDP_FLOOD:$udp_flood_count, TCP_SYN_FLOOD:$tcp_syn_flood_count, AVG_RTT:$rtt_avg"
else
    # Output just the counts if the machine is neither attacker nor benign
    echo "BENIGN:$benign_count, UDP_FLOOD:$udp_flood_count, TCP_SYN_FLOOD:$tcp_syn_flood_count"
fi

# Delete temporary files
rm -f /tmp/capture.pcap
rm -f /tmp/playlist.json
rm -f /tmp/traffic_generator.py
rm -f /tmp/traffic_data.txt
rm -f /tmp/rtt.txt
