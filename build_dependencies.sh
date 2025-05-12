#!/bin/bash -e

cd "$(dirname "$0")"

if [ "$EUID" -ne 0 ]; then
     echo "Please run as root"
     exit 1
fi

function update()(
    URL=$1
    DIR=$2
    build_mode=$3

    if ! [ -d "$DIR" ]; then
        git clone "$URL" "$DIR"
        cd "$DIR"
    else
        cd "$DIR"
        git remote update

        UPSTREAM='@{u}'
        LOCAL=$(git rev-parse @)
        REMOTE=$(git rev-parse "$UPSTREAM")

        if [ "$LOCAL" != "$REMOTE" ]; then
            echo "Updating $DIR"
            git reset --hard origin/HEAD
        fi

    fi

    if [ "$DIR" == "zdns" ]; then
        git checkout "v1.1.0"
    fi
    if [ "$DIR" == "zmapv6" ]; then
        # export CMAKE_C_FLAGS="-Wno-incompatible-pointer-types"
        sed -i 's/cmake_minimum_required(VERSION [0-9.]\+/cmake_minimum_required(VERSION 3.5/' CMakeLists.txt
        sed -i '/^set(GCCWARNINGS$/a     "-Wno-incompatible-pointer-types"' CMakeLists.txt
    fi
    case "$build_mode" in
        cmake) cmake .; make;;
        make) make ;;
        ret) return 0 ;;
        *) echo "Unknown build mode: $build_mode"; exit 1 ;;
    esac
    return 0
)

echo "Updating zmap"
update "https://github.com/zmap/zmap.git" "zmap" cmake

echo "Updating zmapv6"
update "https://github.com/XoMEX/zmapv6.git" "zmapv6" cmake

echo "Updating zdns"
rm -r zdns
update "https://github.com/zmap/zdns.git" "zdns" make

#echo "Updating zgrab2"
#update "https://github.com/zmap/zgrab2.git" "zgrab2" make

force_zgrab2_tls13="$force_build"
if update "https://syssec-vm-deploy:gldt-pKetsVzcvBYAAPVzuXfu@git.cs.uni-paderborn.de/syssec/projects/steckruebe/zcrypto.git" "zcrypto_tls13" ret; then
    force_zgrab2_tls13=true
fi

echo "Updating zgrab13"
if update "https://syssec-vm-deploy:gldt-CT5rxLcLs3n_JT3K6ZkC@git.cs.uni-paderborn.de/syssec/projects/steckruebe/zgrab2.git" "zgrab2_tls13" ret || [ "$force_zgrab2_tls13" == "true" ]; then
    (
        echo "Building zgrab2_tls13"
        cd "zgrab2_tls13"
        sed -i -E 's/replace github.com\/zmap\/zcrypto => .+/replace github.com\/zmap\/zcrypto => ..\/zcrypto_tls13/' go.mod
        make zgrab2
        git restore go.mod
    )
fi

#if ! [ -d /etc/zmap/ ]; then
#    mkdir /etc/zmap/
#fi
#cat > /etc/zmap/zmap.conf << EOF
## ! This file is auto-managed by the scanning-infra repository located at $(pwd)
#### Probe Module to use
##probe-module tcp_synscan


#### Destination port to scan
##target-port 443

#### Scan rate in packets/sec
##rate 10000

#### Scan rate in bandwidth (bits/sec); overrides rate
#bandwidth 1G


#### Blacklist file to use. We encourage you to exclude
#### RFC1918, IANA reserved, and multicast networks,
#### in addition to those who have opted out of your
#### network scans.
##blocklist-file "/data/Crawling-Blacklist/blacklist.txt"

#### Optionally print a summary at the end
##summary
#EOF

# copy binaries to /usr/local/bin

# cp_upgrade_softlink "$(pwd)/zmap/src/zmap" "./zmap"
# cp_upgrade_softlink "$(pwd)/zmapv6/src/zmap" "./zmapv6"
# cp_upgrade_softlink "$(pwd)/zdns/zdns" "./zdns"
# cp_upgrade_softlink "$(pwd)/zgrab2/zgrab2" "./zgrab2"
# cp_upgrade_softlink "$(pwd)/zgrab2_tls13/zgrab2" "./zgrab2_tls13"

# set capabilities for zmap and zmapv6, others work without further permissions
setcap cap_net_raw=eip ./zmapv6/src/zmap
setcap cap_net_raw=eip ./zmap/src/zmap
