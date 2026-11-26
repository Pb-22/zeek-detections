@load ./wire
module Iodine;
# Every persistent object has a bounded owning pool. Queue links are updated on
# every insertion/removal; no append only eviction journal or per key timers.
type Fragment: record {
 seq: count &default=99; poisoned: bool &default=F;
 hashes: table[count] of string &default=table();
 lengths: table[count] of count &default=table();
 starts: table[count] of string &default=table();
 finals: table[count] of bool &default=table();
 complete: bool &default=F; last: count &default=99; bytes: count &default=0;
 acked: bool &default=F;
};
type Session: record {
 client: addr; server: addr; suffix: string; uid: count;
 epoch: count; serial: count; version_token: string; touched: time;
 login: string &default=""; upstream: string &default="Base32";
 downstream: string &default=""; done: bool &default=F;
 up: Fragment &default=[]; down: Fragment &default=[];
 rawserver: addr &optional; rawquery: string &default="";
 rawpaired: bool &default=F; rawup: count &default=0; rawdown: count &default=0;
};
type Candidate: record {
 client: addr; server: addr; suffix: string; serial: count; token: string;
 assigned: bool &default=F; uid: count &default=99; epoch: count &default=0;
 touched: time; prev: string &default=""; following: string &default="";
};
type Pending: record {
 command: string; suffix: string; switch_value: string &default="";
 client: addr; server: addr; born: time; candidate: string &default="";
 session: string &default=""; epoch: count &default=0;
 protected: bool &default=F; prev: string &default=""; following: string &default="";
};
global candidates: table[string] of Candidate=table();
global pending: table[string] of Pending=table();
global sessions: table[string] of Session=table();
global chead=""; global ctail="";
global phead: table[bool] of string = { [F]="", [T]="" };
global ptail: table[bool] of string = { [F]="", [T]="" };
global serial: count=0; global generation: count=0;
global pending_peak: count=0; global candidate_peak: count=0; global session_peak: count=0;
global degraded: count=0; global rejected_large: count=0; global integrity_errors: count=0;
function peaks()
 {
 if (|pending|>pending_peak) pending_peak=|pending|;
 if (|candidates|>candidate_peak) candidate_peak=|candidates|;
 if (|sessions|>session_peak) session_peak=|sessions|;
 }
function premove(key: string)
 {
 if (key !in pending) { ++integrity_errors; return; }
 local p=pending[key]; local pool=p$protected;
 if (p$prev!="") { if (p$prev in pending) pending[p$prev]$following=p$following; else ++integrity_errors; }
 else phead[pool]=p$following;
 if (p$following!="") { if (p$following in pending) pending[p$following]$prev=p$prev; else ++integrity_errors; }
 else ptail[pool]=p$prev;
 delete pending[key];
 }
function cremove(key: string)
 {
 if (key !in candidates) { ++integrity_errors; return; }
 local c=candidates[key];
 if (c$prev!="") { if (c$prev in candidates) candidates[c$prev]$following=c$following; else ++integrity_errors; }
 else chead=c$following;
 if (c$following!="") { if (c$following in candidates) candidates[c$following]$prev=c$prev; else ++integrity_errors; }
 else ctail=c$prev;
 delete candidates[key];
 }
function sinvalidate(key: string)
 {
 if (key !in sessions) return;
 # Pending entries retain admission epoch, and removal also releases links.
 local remove: vector of string=vector();
 for (p in pending) if (pending[p]$session==key) remove[|remove|]=p;
 for (i in remove) premove(remove[i]);
 delete sessions[key];
 }
function expire()
 {
 local now=network_time(); local remove: vector of string=vector();
 for (p in pending) if (now-pending[p]$born>=pending_ttl_seconds) remove[|remove|]=p;
 for (i in remove) premove(remove[i]);
 remove=vector();
 for (c in candidates) if (now-candidates[c]$touched>=candidate_ttl_seconds) remove[|remove|]=c;
 for (i in remove) cremove(remove[i]);
 remove=vector();
 for (s in sessions) if (now-sessions[s]$touched>=session_idle_seconds) remove[|remove|]=s;
 for (i in remove) sinvalidate(remove[i]);
 }
function padd(key: string, p: Pending): bool
 {
 if (key in pending) return T;
 if (pending_limit==0) { ++degraded; return F; }
 if (|pending|>=pending_limit) {
  if (phead[F]!="") { premove(phead[F]); ++degraded; }
  else { ++degraded; return F; }
 }
 local pool=p$protected; p$prev=ptail[pool];
 if (p$prev!="") pending[p$prev]$following=key; else phead[pool]=key;
 ptail[pool]=key; pending[key]=p; peaks(); return T;
 }
function cadd(key: string, c: Candidate): bool
 {
 if (key in candidates) return T;
 if (candidate_limit==0) { ++degraded; return F; }
 if (|candidates|>=candidate_limit) { cremove(chead); ++degraded; }
 c$prev=ctail;
 if (ctail!="") candidates[ctail]$following=key; else chead=key;
 ctail=key; candidates[key]=c; peaks(); return T;
 }
function skey(client: addr, server: addr, suffix: string, uid: count): string
 { return fmt("%s|%s|%s|%d",client,server,suffix,uid); }
function pkey(client: addr, server: addr, cp: port, sp: port, d: DNSWire): string
 { return fmt("%s|%s|%s|%s|%d|%s",client,server,cp,sp,d$id,sha256_hash(d$question)); }
function suffix_ok(s: string): bool
 { return |s|>0 && /^[a-z0-9_][a-z0-9_.-]*$/ == s; }
function prefix_for(labels: vector of string, suffix: string): string
 {
 local i: count=1;
 while (i<|labels|) {
  if (to_lower(joinlabels(labels,i,|labels|,"."))==suffix) return joinlabels(labels,0,i,"");
  ++i;
 }
 return "";
 }
function login_ok(s: string): bool
 {
 if (|s|>80 || !(/^[0-9.]+-[0-9.]+-[0-9]+-[0-9]+$/ == s)) return F;
 local fields=split_string(s,/-/); if (|fields|!=4) return F;
 local j: count=0;
 while (j<2) {
  local parts=split_string(fields[j],/\./); if (|parts|!=4) return F;
  for (k in parts) if (|parts[k]|==0 || |parts[k]|>3 || to_count(parts[k])>255) return F;
  ++j;
 }
 return to_count(fields[2])>0 && to_count(fields[2])<=65535 && to_count(fields[3])>=1 && to_count(fields[3])<=32;
 }
function fragment(f: Fragment, seq: count, frag: count, final: bool, body: string): Fragment
 {
 if (|body|==0 || frag>=16 || frag>=bounded_fragment_slots_per_session/2) return f;
 if (seq!=f$seq) f=[$seq=seq];
 if (f$poisoned) return f;
 local hash=sha256_hash(body);
 if (frag in f$hashes) {
  if (f$hashes[frag]!=hash || f$finals[frag]!=final) { f$poisoned=T; f$complete=F; f$acked=F; }
  return f;
 }
 f$hashes[frag]=hash; f$lengths[frag]=|body|; f$starts[frag]=cut(body,0,|body|<2 ? |body| : 2); f$finals[frag]=final;
 # A new fragment changes the packet's evidence, including an earlier final.
 # Requalify from all retained slots before a later ACK can count this packet.
 f$complete=F; f$acked=F; f$last=99; f$bytes=0;
 local i: count=0; local bytes: count=0; local head=""; local last: count=99;
 while (i<16 && i in f$hashes) {
  bytes+=f$lengths[i];
  if (|head|<2) { local n=2-|head|; if (n>|f$starts[i]|) n=|f$starts[i]|; head+=cut(f$starts[i],0,n); }
  if (f$finals[i]) { last=i; break; } ++i;
 }
 if (last!=99 && |f$hashes|==last+1 && zheader(head,bytes)) { f$complete=T; f$last=last; f$bytes=bytes; }
 return f;
 }
function ack(f: Fragment, seq: count, frag: count): Fragment
 { if (f$complete && f$seq==seq && f$last==frag) f$acked=T; return f; }
function maybe_notice(key: string, raw: bool)
 {
 if (key !in sessions) return;
 local s=sessions[key]; if (s$done || s$login=="") return;
 if (raw) { if (!s$rawpaired || s$rawup==0 || s$rawdown==0 || !s?$rawserver) return; }
 else if (!s$up$complete || !s$down$complete || !s$up$acked || !s$down$acked) return;
 local up=s$up$bytes; local down=s$down$bytes; local uf=s$up$last+1; local df=s$down$last+1;
 local uc=s$upstream; local dc=s$downstream; local transport="dns"; local dst=s$server;
 if (raw) { up=s$rawup; down=s$rawdown; uf=1; df=1; uc="Raw"; dc="Raw"; transport="raw"; dst=s$rawserver; }
 NOTICE([$note=CompatibleSession,
  $msg="iodine session pattern observed: matched negotiation followed by two way tunnel traffic",
  $sub=fmt("evidence=version,login,data_up,data_down;transport=%s;suffix=%s;userid=%d;upstream=%s;downstream=%s;version=0x00000502;login=%s;up_bytes=%d;down_bytes=%d;up_fragments=%d;down_fragments=%d",transport,s$suffix,s$uid,uc,dc,s$login,up,down,uf,df),
  $src=s$client,$dst=dst,$identifier=fmt("%s|epoch=%d",key,s$epoch)]);
 sessions[key]$done=T;
 }
function request(client: addr, server: addr, cp: port, sp: port, d: DNSWire)
 {
 if (|d$labels|<2) return;
 local token=pkey(client,server,cp,sp,d);
 if (token in pending) return;
 local first=d$labels[0]; local cmd=to_lower(cut(first,0,1));
 if (cmd=="v" && |first|==11) {
  local ver=decode(cut(first,1,10),"Base32");
  local suffix=to_lower(joinlabels(d$labels,1,|d$labels|,"."));
  if (!ver$ok || |ver$data|!=6 || bytestring_to_count(cut(ver$data,0,4))!=1282 || !suffix_ok(suffix)) return;
  local ct=fmt("%s|%s|%s|%s",client,server,suffix,sha256_hash(d$question));
  # Exact retransmissions preserve the first version serial and generation.
  local active=F;
  for (s in sessions) if (sessions[s]$version_token==ct) active=T;
  if (active) return;
  ++serial;
  if (!cadd(ct,[$client=client,$server=server,$suffix=suffix,$serial=serial,$token=ct,$touched=network_time()])) return;
  padd(token,[$command="v",$suffix=suffix,$client=client,$server=server,$born=network_time(),$candidate=ct]); return;
 }
 # Resolve a command only within an assigned observed peer and suffix context.
 local sid=""; local prefix=""; local uid: count=99;
 for (s in sessions) {
  if (sessions[s]$client!=client || sessions[s]$server!=server) next;
  local pre=prefix_for(d$labels,sessions[s]$suffix); if (pre=="") next;
  local decoded: Decoded=[]; local id: count=99;
  if (cmd=="l" || cmd=="p" || cmd=="n") { decoded=decode(cut(pre,1,|pre|-1),"Base32"); if (decoded$ok && |decoded$data|>0) id=oct(decoded$data,0); }
  else if (cmd=="i" || cmd=="s" || cmd=="o") { if (|pre|>1) id=b32val(cut(pre,1,1)); }
  else if (/^[0-9a-f]$/ == cmd) { id=to_count(cmd,16); }
  if (id==sessions[s]$uid) { sid=s; prefix=pre; uid=id; break; }
 }
 # Keep the wire command unchanged while every possible userid is scanned.
 if (/^[0-9a-f]$/ == cmd) cmd="data";
 if (sid=="" && cmd=="l") {
  local chosen=""; local latest: count=0;
  for (c in candidates) {
   local ca=candidates[c]; if (!ca$assigned || ca$client!=client || ca$server!=server) next;
   local cpre=prefix_for(d$labels,ca$suffix); if (|cpre|!=32) next;
   local login=decode(cut(cpre,1,31),"Base32");
   if (login$ok && |login$data|==19 && oct(login$data,0)==ca$uid && ca$serial>latest) { chosen=c; latest=ca$serial; prefix=cpre; }
  }
  if (chosen!="") {
   local admitted=candidates[chosen]; sid=skey(client,server,admitted$suffix,admitted$uid); uid=admitted$uid;
   if (sid !in sessions && |sessions|>=session_limit) { ++degraded; return; }
   sessions[sid]=[$client=client,$server=server,$suffix=admitted$suffix,$uid=admitted$uid,$epoch=admitted$epoch,$serial=admitted$serial,$version_token=admitted$token,$touched=network_time()];
   cremove(chosen); peaks();
  }
 }
 if (sid=="" || sid !in sessions) return;
 local sess=sessions[sid];
 if (cmd=="l") {
  local l=decode(cut(prefix,1,|prefix|-1),"Base32"); if (!l$ok || |l$data|!=19 || oct(l$data,0)!=sess$uid) return;
 } else if (sess$login=="") return;
 if (cmd !in set("l","i","s","o","p","data","n")) return;
 # Only codec switches need a query value at reply time. Login digests and
 # encoded fragment bodies remain local to this request callback.
 local switch_value="";
 if ((cmd=="s" || cmd=="o") && |prefix|==7) switch_value=cut(prefix,2,1);
 if (!padd(token,[$command=cmd,$suffix=sess$suffix,$switch_value=switch_value,$client=client,$server=server,$born=network_time(),$session=sid,$epoch=sess$epoch,$protected=T])) return;
 sessions[sid]$touched=network_time();
 if (cmd=="data" && |prefix|>=5 && sess$downstream!="") {
  local a=b32val(cut(prefix,1,1)); local b=b32val(cut(prefix,2,1)); local e=b32val(cut(prefix,3,1));
  if (a>31 || b>31 || e>31) return;
  local body=decode(cut(prefix,5,|prefix|-5),sess$upstream);
  if (!body$ok) return;
  sessions[sid]$down=ack(sessions[sid]$down,b%8,e/2);
  sessions[sid]$up=fragment(sessions[sid]$up,a/4,(a%4)*4+b/8,e%2==1,body$data);
 } else if (cmd=="p" && |prefix|==8) {
  local ping=decode(cut(prefix,1,7),"Base32");
  if (ping$ok && |ping$data|==4 && oct(ping$data,0)==uid) sessions[sid]$down=ack(sessions[sid]$down,(oct(ping$data,1)/16)%8,oct(ping$data,1)%16);
 }
 maybe_notice(sid,F);
 }
function response(client: addr, server: addr, cp: port, sp: port, d: DNSWire)
 {
 local token=pkey(client,server,cp,sp,d); if (token !in pending) return;
 local p=pending[token]; premove(token);
 if (!d$answer$ok) return;
 local body=d$answer$data; local sid=p$session; local codec="";
 if (p$command=="v") {
  if (p$candidate !in candidates || |body|!=9 || cut(body,0,4)!="VACK" || oct(body,8)>15) return;
  local c=candidates[p$candidate]; local uid=oct(body,8); sid=skey(client,server,c$suffix,uid);
  if (sid in sessions && c$serial<=sessions[sid]$serial) return;
  ++generation;
  candidates[p$candidate]$assigned=T; candidates[p$candidate]$uid=uid; candidates[p$candidate]$epoch=generation;
  candidates[p$candidate]$touched=network_time();
  if (sid in sessions) {
   sinvalidate(sid);
   sessions[sid]=[$client=client,$server=server,$suffix=c$suffix,$uid=uid,$epoch=generation,$serial=c$serial,$version_token=c$token,$touched=network_time()];
   cremove(p$candidate); peaks();
  }
  return;
 }
 if (sid !in sessions || p$epoch!=sessions[sid]$epoch) return;
 local s=sessions[sid];
 if (p$command=="l") {
  if (!login_ok(body)) return;
  sessions[sid]$login=body;
  # NULL and PRIVATE carry raw reply bytes by their actual RR types.
  if (d$qtype==10 || d$qtype==65399) sessions[sid]$downstream="Raw";
  else sessions[sid]$downstream=d$answer$codec;
 } else if (s$login=="") return;
 else if (p$command=="i" && cut(body,0,1)=="I") {
  if (|body|==5) sessions[sid]$rawserver=count_to_v4_addr(bytestring_to_count(cut(body,1,4)));
 } else if (p$command=="s" && p$switch_value!="") {
  local value=b32val(p$switch_value);
  if (value==5) codec="Base32"; else if (value==6) codec="Base64"; else if (value==26) codec="Base64u"; else if (value==7) codec="Base128";
  if (codec!="" && body==codec) sessions[sid]$upstream=codec;
 } else if (p$command=="o" && p$switch_value!="") {
  local opt=to_lower(p$switch_value);
  if (opt=="t") codec="Base32"; else if (opt=="s") codec="Base64"; else if (opt=="u") codec="Base64u"; else if (opt=="v") codec="Base128"; else if (opt=="r") codec="Raw";
  if (codec!="" && body==codec && d$answer$codec==codec) sessions[sid]$downstream=codec;
 } else if ((p$command=="p" || p$command=="data") && |body|>=2 && s$downstream!="" && d$answer$codec==s$downstream && oct(body,0)>=128) {
  sessions[sid]$up=ack(sessions[sid]$up,(oct(body,0)/16)%8,oct(body,0)%16);
  sessions[sid]$down=fragment(sessions[sid]$down,oct(body,1)/32,(oct(body,1)/2)%16,oct(body,1)%2==1,cut(body,2,|body|-2));
 }
 sessions[sid]$touched=network_time(); maybe_notice(sid,F);
 }
function rawpacket(client: addr, server: addr, up: bool, payload: string)
 {
 if (|payload|<4 || cut(payload,0,3)!="\x10\xd1\x9e") return;
 local uid=oct(payload,3)%16; local command=(oct(payload,3)/16)*16;
 local chosen=""; local matches: count=0;
 for (candidate_session in sessions) {
  local ss=sessions[candidate_session];
  if (ss$client==client && ss?$rawserver && ss$rawserver==server && ss$uid==uid && ss$login!="") { chosen=candidate_session; ++matches; }
 }
 if (matches!=1) return;
 local body=cut(payload,4,|payload|-4); local s=sessions[chosen];
 if (command==16 && |body|==16) {
  if (up) sessions[chosen]$rawquery=sha256_hash(body);
  else if (s$rawquery!="" && s$rawquery!=sha256_hash(body)) sessions[chosen]$rawpaired=T;
 } else if (command==32 && |payload|<=4096 && s$rawpaired && zheader(body,|body|)) {
  if (up) sessions[chosen]$rawup=|body|; else sessions[chosen]$rawdown=|body|;
 } else if (command!=48 || |payload|!=4) return;
 sessions[chosen]$touched=network_time(); maybe_notice(chosen,T);
 }
function integrity()
 {
 local visited: set[string]=set(); local current=chead; local previous=""; local n: count=0;
 while (current!="" && n<=|candidates|) {
  if (current !in candidates || current in visited) { ++integrity_errors; break; }
  add visited[current]; if (candidates[current]$prev!=previous) ++integrity_errors;
  previous=current; current=candidates[current]$following; ++n;
 }
 if (n!=|candidates| || previous!=ctail || current!="") ++integrity_errors;
 visited=set();
 for (pool in phead) {
  current=phead[pool]; previous=""; n=0;
  while (current!="" && n<=|pending|) {
   if (current !in pending || current in visited) { ++integrity_errors; break; }
   add visited[current];
   if (pending[current]$prev!=previous || pending[current]$protected!=pool) ++integrity_errors;
   previous=current; current=pending[current]$following; ++n;
  }
  if (previous!=ptail[pool] || current!="") ++integrity_errors;
 }
 if (|visited|!=|pending|) ++integrity_errors;
 }
event sweep()
 { expire(); if (sweep_interval_seconds>0secs) schedule sweep_interval_seconds { sweep() }; }
event zeek_init() { if (sweep_interval_seconds>0secs) schedule sweep_interval_seconds { sweep() }; }
event zeek_done()
 {
 expire(); integrity();
 print fmt("IODINE_HEALTH {\"pending_peak\":%d,\"candidate_peak\":%d,\"session_peak\":%d,\"pending_final\":%d,\"candidate_final\":%d,\"session_final\":%d,\"degraded\":%d,\"rejected_large\":%d,\"integrity_errors\":%d}",pending_peak,candidate_peak,session_peak,|pending|,|candidates|,|sessions|,degraded,rejected_large,integrity_errors);
 }
