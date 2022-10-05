!/usr/bin/env bash
make dns
for f in ring*; do tshark -r $f -Y "dns" -w ~/data/RingBuffer/dns/dns-$f;done
mergecap -w ~/data/RingBuffer/dns/alldns.pcapng ~/data/RingBuffer/dns/*
rm ~/data/RingBuffer/dns/dns-*
mkdir strangeports
for f in ring*; do tshark -r $f -Y "!tcp.port in {22,23,25,80,443,445,993,995,8000..8005}" -w ~/data/RingBuffer/strangeports/strangeports-$f;done
mergecap -w ~/data/RingBuffer/strangeports/allstrangeports.pcapng ~/data/RingBuffer/strangeports/*
rm ~/data/RingBuffer/strangeports/strangeports-*
mkdir TLSVersion
for f in ring*; do tshark -r $f -Y "tls.handshake.version < 0x0303" -w ~/data/RingBuffer/TLSVersion/TLSVer-$f;done
mergecap -w ~/data/RingBuffer/TLSVersion/allTLSVer.pcapng ~/data/RingBuffer/TLSVersion/*
rm ~/data/RingBuffer/TLSVersion/TLSVer-*
for f in ring*; do tshark -r $f -Y "tcp.flags.syn=1 and tcp.flags.ack==0 and tcp.window_size<=1024" -w ~/data/RingBuffer/nmapscan/nmap-$f;done
mergecap -w ~/data/RingBuffer/nmapscan/allnmap.pcapng ~/data/RingBuffer/nmapscan/*
rm ~/data/RingBuffer/nmapscan/nmap-*
for f in ring*; do tshark -r $f -Y "ip.geo.country_iso in {CN,NK,RU}" -w ~/data/RingBuffer/badcountry/country-$f;done
mergecap -w ~/data/RingBuffer/badcountry/allcn.pcapng ~/data/RingBuffer/badcountry/*
rm ~/data/RingBuffer/badcountry/country-*
