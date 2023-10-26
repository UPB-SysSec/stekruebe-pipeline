#!/bin/sh -e
cd "$(dirname "$0")"
if ! [ -d out ];then
    mkdir out
fi

FN_TRANCO="tranco_LYK84.csv"
FN_BLOCKLIST_4="/data/Crawling-Blacklist/blacklist.txt"
FN_BLOCKLIST_6="/data/Crawling-Blacklist/blacklist-ipv6.txt"

# echo "[!] DEBUG VALUES ACTIVE"
# echo "[!] DEBUG VALUES ACTIVE"
# FN_TRANCO="tranco_LYK84_head.csv"
# FN_BLOCKLIST_4="testblocklist.ipv4"
# FN_BLOCKLIST_6="testblocklist.ipv6"
# echo "[!] DEBUG VALUES ACTIVE"
# echo "[!] DEBUG VALUES ACTIVE"

# workflow:
# everything is done twice except stated otherwise (once v4, once v6)
# - resolve (combined v4/v6)
# - transform to zmap format (split v4/v6)
# - fliter with blocklist
# - zmap (with blocklist passed, but shouldn't be necessary)
# - merge v4 and v6
# - map open ips to their domains again
# - zgrab merged (v4 and v6)

FN_RESOLVED_JSON="out/0_resolved.json"

FN_RESOLVED_4_IPLIST="out/1_resolved_v4.ips"
FN_FILTERED_4_IPLIST="out/2_resolved_filtered_v4.ips"
FN_HTTPS_4_IPLIST="out/3_https_hosts_v4.ips"

FN_RESOLVED_6_IPLIST="out/1_resolved_v6.ips"
FN_FILTERED_6_IPLIST="out/2_resolved_filtered_v6.ips"
FN_HTTPS_6_IPLIST="out/3_https_hosts_v6.ips"

FN_MERGED_IP_LIST="out/4_merged.ips"
FN_MERGED_HOST_LIST="out/5_merged.csv"
FN_ZGRAB_OUT="out/6_zgrab.json"
FN_ZGRAB_MERGED_OUT="out/7_merged_zgrab.json"


## 1. Resolve domains 
if ! [ -f $FN_TRANCO ];then
    echo "[!] Tranco file not found"
    exit 1
fi

if ! [ -f $FN_RESOLVED_JSON ];then
    echo "[ ] Resolving Domains"
    date
    cat $FN_TRANCO | ~/zdns/zdns --iterative --alexa alookup --ipv6-lookup --ipv4-lookup > $FN_RESOLVED_JSON
    date
    echo "[+] Resolved Domains"
else
    echo "[.] Using Cached resolved Domains"
fi

# 1.1 Convert and Filter Domains

echo "[ ] Converting for zmap"
cat $FN_RESOLVED_JSON | jq -r ".data.ipv4_addresses | select(. != null) | .[]" > $FN_RESOLVED_4_IPLIST
cat $FN_RESOLVED_JSON | jq -r ".data.ipv6_addresses | select(. != null) | .[]" > $FN_RESOLVED_6_IPLIST
# cat $FN_RESOLVED_JSON | jq -r '.data.answers | select(. != null) | .[] | select(.type == "AAAA") | .answer' > $FN_RESOLVED_6_IPLIST
# cat $FN_RESOLVED_6_IPLIST | jq -r ".data.ipv4_addresses | select(. != null) | .[]" > $FN_RESOLVED_6_IPLIST
echo "[ ] Filtering blocked IPs"
# filter v4/v6 TODO
cat $FN_RESOLVED_4_IPLIST | python3 scripts/0_filter_blocklist.py $FN_BLOCKLIST_4 > $FN_FILTERED_4_IPLIST
cat $FN_RESOLVED_6_IPLIST | python3 scripts/0_filter_blocklist.py $FN_BLOCKLIST_6 > $FN_FILTERED_6_IPLIST

## 2. Check Ports
echo "[ ] Checking open ports"
if ! [ -f $FN_HTTPS_4_IPLIST ];then
    date
    ~/zmap/src/zmap -b $FN_BLOCKLIST_4 -p 443 -w $FN_FILTERED_4_IPLIST -o $FN_HTTPS_4_IPLIST
    date
else
    echo "[.] Using Cached IPv4 open ports"
fi
echo "[.] Done With IPv4, continuing to IPv6"
if ! [ -f $FN_HTTPS_6_IPLIST ];then
    # Blocklist in v6 does not work :weary: But we filtered earlier, so it should be fine
    # -b $FN_BLOCKLIST_6
    date
    ~/zmapv6/src/zmap -M ipv6_tcp_synscan -p 443 --ipv6-source-ip "2001:638:502:28:250:56ff:feb8:97ec" --ipv6-target-file $FN_FILTERED_6_IPLIST -o $FN_HTTPS_6_IPLIST
    date
else
    echo "[.] Using Cached IPv6 open ports"
fi
echo "[+] Checked open ports"


## 2.1 Merge IPv4 and IPv6
echo "[ ] Merging IPv4 and IPv6"
cat $FN_HTTPS_4_IPLIST $FN_HTTPS_6_IPLIST | sort -u > $FN_MERGED_IP_LIST
echo "[ ] Mapping IPs to Domains"
python3 scripts/1_create_zgrabhosts.py $FN_RESOLVED_JSON $FN_MERGED_IP_LIST $FN_MERGED_HOST_LIST

## 3. Get Stats
echo "[ ] Running zgrab"
if ! [ -f $FN_ZGRAB_OUT ];then
    date
    cat $FN_MERGED_HOST_LIST | ~/zgrab2/zgrab2 tls --session-ticket --connections-per-host=5 > $FN_ZGRAB_OUT
    date
else
    echo "[.] Using Cached zgrab output"
fi
echo "[+] Done running zgrab"

## 3.1 Postprocessing
echo "[ ] Merging zgrab output per domain,ip pair"
python3 scripts/2_postprocess_zgrab.py $FN_ZGRAB_OUT $FN_ZGRAB_MERGED_OUT

echo "[#] Done"
