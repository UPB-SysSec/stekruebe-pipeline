# check if hosts.txt exists
if [ ! -f "$PWD/hosts.txt" ]; then
  echo "Error: $PWD/hosts.txt not found!"
  exit 1
fi

docker run -d --name stekruebe-dnsmasq \
  --network stekruebe-dummy-servers_steknet \
  --rm \
  -v "$PWD/hosts.txt:/etc/hosts:ro" \
  -p 8053:53/udp \
  andyshinn/dnsmasq \
  -k --log-facility=- --no-resolv --addn-hosts=/etc/hosts
