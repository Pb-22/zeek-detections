@load base/protocols/dns
@load base/frameworks/notice
module Iodine;
export {
 redef enum Notice::Type += { CompatibleSession };
 const ports: set[port] = { 53/udp } &redef;
}
redef udp_content_ports += { 53/udp };
@load ./state

global next_expiry: time = double_to_time(0);
event udp_contents(c: connection, is_orig: bool, contents: string)
 {
 if (network_time()>=next_expiry) { expire(); next_expiry=network_time()+sweep_interval_seconds; }
 local src=c$id$orig_h; local dst=c$id$resp_h;
 local sport=c$id$orig_p; local dport=c$id$resp_p;
 if (!is_orig) { src=c$id$resp_h; dst=c$id$orig_h; sport=c$id$resp_p; dport=c$id$orig_p; }
 if (sport !in ports && dport !in ports) return;
 if (|contents|>max_datagram_bytes) { ++rejected_large; return; }
 if (cut(contents,0,3)=="\x10\xd1\x9e") {
  if (dport in ports) rawpacket(src,dst,T,contents);
  else rawpacket(dst,src,F,contents);
  return;
 }
 local d=dnswire(contents); if (!d$ok) return;
 if (d$reply && sport in ports) response(dst,src,dport,sport,d);
 else if (!d$reply && dport in ports) request(src,dst,sport,dport,d);
 }
event zeek_init() &priority=10 { udp_content_ports += ports; }
