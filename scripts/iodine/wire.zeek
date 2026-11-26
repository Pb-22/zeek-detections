# Stock Zeek byte oriented DNS and iodine codec primitives.
module Iodine;
export {
 const pending_limit: count = 1024 &redef;
 const candidate_limit: count = 256 &redef;
 const session_limit: count = 256 &redef;
 const candidate_ttl_seconds: interval = 30secs &redef;
 const pending_ttl_seconds: interval = 30secs &redef;
 const session_idle_seconds: interval = 300secs &redef;
 const max_dns_name_bytes: count = 255 &redef;
 const max_dns_records: count = 16 &redef;
 const max_dns_pointer_jumps: count = 10 &redef;
 const max_datagram_bytes: count = 8192 &redef;
 const bounded_fragment_slots_per_session: count = 32 &redef;
 const sweep_interval_seconds: interval = 1secs &redef;
}
# All internal offsets are zero based. sub_bytes itself is one based.
function cut(s: string, o: count, n: count): string
 { if (o > |s| || n > |s|-o) return ""; return sub_bytes(s,o+1,n); }
function oct(s: string, o: count): count
 { return bytestring_to_count(cut(s,o,1)); }
function u16(s: string, o: count): count
 { return bytestring_to_count(cut(s,o,2)); }
function chr(n: count): string { return hexstr_to_bytestring(fmt("%02x",n)); }
const b32 = "abcdefghijklmnopqrstuvwxyz012345";
const b64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789+";
const b64u = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789_";
# Extended alphabet is specified by src/base128.c, not a Unicode mapping.
global b128 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
type Decoded: record { ok: bool &default=F; data: string &default=""; codec: string &default=""; };
function b32val(s: string): count
 { local i=find_str(b32,to_lower(s)); if (i<0 || |s|!=1) return 99; return int_to_count(i); }
function decode(s: string, codec: string): Decoded
 {
 if (codec=="Raw") return [$ok=T,$data=s,$codec=codec];
 local alphabet=b32; local width: count=5;
 if (codec=="Base64") { alphabet=b64; width=6; }
 else if (codec=="Base64u") { alphabet=b64u; width=6; }
 else if (codec=="Base128") { alphabet=b128; width=7; }
 else if (codec!="Base32") return [];
 local acc: count=0; local bits: count=0; local out="";
 local i: count=0; local scale: count=32;
 if (width==6) scale=64; else if (width==7) scale=128;
 while (i<|s|) {
  local c=cut(s,i,1); if (codec=="Base32") c=to_lower(c);
  local v=find_str(alphabet,c); if (v<0) return [];
  acc=acc*scale+int_to_count(v); bits+=width;
  if (bits>=8) { bits-=8; local divisor: count=1; local j: count=0; while (j<bits) { divisor=divisor*2; ++j; } out+=chr(acc/divisor); acc=acc%divisor; }
  ++i;
 }
 # Native decoding counts complete bytes; reject symbols outside the alphabet.
 return [$ok=T,$data=out,$codec=codec];
 }
type Name: record { ok: bool &default=F; end: count &default=0; labels: vector of string &default=vector(); raw: string &default=""; };
function name(s: string, start: count): Name
 {
 local pos=start; local stop: count=0; local jumps: count=0;
 local seen: set[count]=set(); local labels: vector of string=vector();
 local raw=""; local expanded: count=1;
 while (pos<|s|) {
  if (pos in seen) return []; add seen[pos];
  local n=oct(s,pos);
  if (n>=192) {
   if (pos+2>|s| || jumps>=max_dns_pointer_jumps) return [];
   if (stop==0) stop=pos+2;
   pos=(n%64)*256+oct(s,pos+1); ++jumps; next;
  }
  ++pos;
  if (n==0) { if (stop==0) stop=pos; return [$ok=T,$end=stop,$labels=labels,$raw=raw+"\x00"]; }
  if (n>63 || pos+n>|s| || expanded+n+1>max_dns_name_bytes) return [];
  labels[|labels|]=cut(s,pos,n); raw+=chr(n)+cut(s,pos,n); expanded+=n+1; pos+=n;
 }
 return [];
 }
function joinlabels(labels: vector of string, first: count, last: count, sep: string): string
 {
 local s=""; local i=first;
 while (i<last) { if (i>first) s+=sep; s+=labels[i]; ++i; } return s;
 }
function marked(s: string, host: bool): Decoded
 {
 if (|s|<1) return [];
 local mark=to_lower(cut(s,0,1)); local codec="";
 if (host) {
  if (mark=="h") codec="Base32"; else if (mark=="i") codec="Base64";
  else if (mark=="j") codec="Base64u"; else if (mark=="k") codec="Base128";
 } else {
  if (mark=="t") codec="Base32"; else if (mark=="s") codec="Base64";
  else if (mark=="u") codec="Base64u"; else if (mark=="v") codec="Base128"; else if (mark=="r") codec="Raw";
 }
 return decode(cut(s,1,|s|-1),codec);
 }
type DNSWire: record {
 ok: bool &default=F; reply: bool &default=F; id: count &default=0;
 qtype: count &default=0; qclass: count &default=0;
 labels: vector of string &default=vector(); question: string &default="";
 answer: Decoded &default=[];
};
function dnswire(s: string): DNSWire
 {
 if (|s|<12 || u16(s,4)!=1) return [];
 local flags=u16(s,2);
 if ((flags/2048)%16!=0 || flags%16!=0 || (flags/512)%2!=0) return [];
 local an=u16(s,6); local ns=u16(s,8); local ar=u16(s,10);
 if (an+ns+ar>max_dns_records) return [];
 local q=name(s,12); if (!q$ok || q$end+4>|s|) return [];
 local qt=u16(s,q$end); local qc=u16(s,q$end+2);
 if (qc!=1 || qt !in set(1,5,10,15,16,33,65399)) return [];
 local pos=q$end+4; local idx: count=0;
 local parts: table[count] of string=table(); local piececodec=""; local valid=T; local found=F;
 while (idx<an+ns+ar) {
  local owner=name(s,pos); if (!owner$ok || owner$end+10>|s|) return [];
  pos=owner$end;
  local typ=u16(s,pos); local cls=u16(s,pos+2); local n=u16(s,pos+8); pos+=10;
  if (n>|s|-pos) return [];
  if (idx<an && cls==1 && owner$raw==q$raw) {
   local d: Decoded=[]; local rank: count=10;
   if ((qt==10 || qt==65399) && typ==qt) d=decode(cut(s,pos,n),"Raw");
   else if (qt==16 && typ==16) {
    local j: count=0; local text="";
    while (j<n) { local z=oct(s,pos+j); ++j; if (z>n-j) return []; text+=cut(s,pos+j,z); j+=z; }
    d=marked(text,F);
   } else if (((qt==1 || qt==5) && typ==5) || (qt==15 && typ==15) || (qt==33 && typ==33)) {
    local skip: count=0;
    if (typ==15) skip=2; else if (typ==33) skip=6;
    if (n<=skip) return [];
    if (skip>0) rank=u16(s,pos);
    local target=name(s,pos+skip);
    if (!target$ok || target$end!=pos+n || |target$labels|<2 || |target$labels[|target$labels|-1]|!=2) return [];
    d=marked(joinlabels(target$labels,0,|target$labels|-1,""),T);
   }
   if (d$ok) {
    if (rank==0 || rank%10!=0 || rank/10>max_dns_records || rank in parts) valid=F;
    parts[rank]=d$data;
    if (found && d$codec!=piececodec) valid=F;
    piececodec=d$codec; found=T;
   }
  }
  pos+=n; ++idx;
 }
 if (pos!=|s|) return [];
 local answer: Decoded=[];
 if (found && valid) {
  local body=""; local k: count=10;
  while (k in parts) { body+=parts[k]; k+=10; }
  if ((k/10)-1==|parts|) answer=[$ok=T,$data=body,$codec=piececodec];
 }
 return [$ok=T,$reply=flags>=32768,$id=u16(s,0),$qtype=qt,$qclass=qc,$labels=q$labels,$question=q$raw+cut(s,q$end,4),$answer=answer];
 }
function zheader(s: string, length: count): bool
 {
 if (|s|<2 || length<8) return F;
 local a=oct(s,0); local b=oct(s,1);
 return a%16==8 && a/16<=7 && (a*256+b)%31==0 && (b/32)%2==0;
 }
event zeek_init() &priority=20
 { local i: count=188; while (i<=253) { b128+=chr(i); ++i; } }
