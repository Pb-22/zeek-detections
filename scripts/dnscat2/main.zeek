@load base/frameworks/notice
module DNScat2;
export {
    redef enum Notice::Type += { CompatibleSession };
    const max_pending = 1024 &redef;
    const max_candidates = 512 &redef;
    const max_sessions = 256 &redef;
    const pending_ttl = 30sec &redef;
    const candidate_ttl = 30sec &redef;
    const session_ttl = 5min &redef;
    const sweep_interval = 1sec &redef;
    const max_boundaries = 8 &redef;
    const max_frame_bytes = 512 &redef;
    const max_name_bytes = 253 &redef;
    const observation_scope = "local" &redef;
    # Metadata only. No raw query, RR block, public key or encrypted body.
    type Frame: record {
        valid: bool &default=F;
        kind: count &default=255;
        length: count &default=0;
        sid: string &default="";
        key_hash: string &default="";
        suffix: string &default="";
        context: string &default="";
        generation: count &default=0;
        initial_key_hash: string &default="";
        progressed: bool &default=F;
    };
    type Observation: record {
        peers: conn_id;
        uid: string;
        token: string;
        dns_id: count &default=0;
        serial: count &default=0;
        scope: string;
        at: time;
        qtype: count;
        question_hash: string;
        request: Frame;
        reply: Frame &optional;
        reply_at: time &optional;
    };
    # Synchronous LOCAL dispatch seam, not a finalized distributed wire API.
    # Request returns the admitted epoch binding; paired reply returns empty Frame.
    global local_dispatch: function(o: Observation): Frame;
    global dispatch_observation: function(o: Observation): Frame &redef;
    # Standalone uses the native packet clock. An optional finite owner supplies
    # explicitly sorted observation time; no Cluster dependency in this module.
    global lifecycle_time: function(): time = network_time &redef;
}
redef record connection += { dnc_message_ok: bool &default=F; };
type Frames: vector of Frame;
type Pending: record {
    at: time;
    peers: conn_id;
    uid: string;
    observation_token: string;
    dns_id: count;
    serial: count;
    question_hash: string;
    qtype: count;
    frames: Frames;
    question_ok: bool &default=F;
    invalid_response: bool &default=F;
    # Only the live address RR response retains bounded binary chunks until end.
    blocks: table[count] of string &default=table();
    rr_count: count &default=0;
    queued: bool &default=F;
    prev_link: string &default="";
    next_link: string &default="";
};
type Session: record {
    generation: count;
    at: time;
    touched: time;
    client_key: string;
    server_key: string &default="";
    enc: bool &default=F;
    syn: bool &default=F;
    msg: bool &default=F;
    syn_at: time &default=double_to_time(0);
    msg_at: time &default=double_to_time(0);
    done: bool &default=F;
    closed: bool &default=F;
    prev_link: string &default="";
    next_link: string &default="";
};
global pending: table[string] of Pending;
global candidate_states: table[string] of Session;
global sessions: table[string] of Session;
global candidate_head = "";
global candidate_tail = "";
global pending_head = "";
global pending_tail = "";
global next_generation: count = 0;
global next_sweep: time = double_to_time(0);
global transaction_serial: count = 0;
global queries: count = 0;
global boundary_attempts: count = 0;
global valid_frames: count = 0;
global structure_rejected: count = 0;
global pairing_rejected: count = 0;
global pending_admissions: count = 0;
global candidate_admissions: count = 0;
global session_admissions: count = 0;
global pending_overflow: count = 0;
global session_overflow: count = 0;
global pending_expiry: count = 0;
global candidate_expiry: count = 0;
global session_expiry: count = 0;
global candidate_evictions: count = 0;
global pending_evictions: count = 0;
global tombstone_evictions: count = 0;
global candidate_replacements: count = 0;
global epoch_rejected: count = 0;
global coverage_degraded: count = 0;
global retries: count = 0;
global notices: count = 0;
global fins: count = 0;
global address_rejected: count = 0;
global address_duplicates: count = 0;
global peak_pending: count = 0;
global peak_candidates: count = 0;
global peak_sessions: count = 0;

function remove_candidate(k: string)
    {
    if ( k !in candidate_states ) return;
    local s = candidate_states[k];
    if ( s$prev_link != "" ) candidate_states[s$prev_link]$next_link = s$next_link;
    else candidate_head = s$next_link;
    if ( s$next_link != "" ) candidate_states[s$next_link]$prev_link = s$prev_link;
    else candidate_tail = s$prev_link;
    delete candidate_states[k];
    }
function remove_pending(k: string)
    {
    if ( k !in pending ) return;
    local p = pending[k];
    if ( p$queued )
        {
        if ( p$prev_link != "" ) pending[p$prev_link]$next_link = p$next_link;
        else pending_head = p$next_link;
        if ( p$next_link != "" ) pending[p$next_link]$prev_link = p$prev_link;
        else pending_tail = p$prev_link;
        }
    delete pending[k];
    }
function sweep()
    {
    if ( lifecycle_time() < next_sweep ) return;
    next_sweep = lifecycle_time() + sweep_interval;
    local pp: set[string] = set();
    local cc: set[string] = set();
    local ss: set[string] = set();
    for ( p in pending )
        if ( lifecycle_time() - pending[p]$at >= pending_ttl ) add pp[p];
    for ( c in candidate_states )
        if ( lifecycle_time() - candidate_states[c]$at >= candidate_ttl ) add cc[c];
    for ( s in sessions )
        if ( lifecycle_time() - sessions[s]$touched >= session_ttl ) add ss[s];
    for ( pk in pp ) { remove_pending(pk); ++pending_expiry; }
    for ( ck in cc ) { remove_candidate(ck); ++candidate_expiry; }
    for ( sk in ss ) { delete sessions[sk]; ++session_expiry; }
    }
function parse_hex(h: string): Frame
    {
    local f: Frame;
    # hexstr_to_bytestring has undefined behavior for invalid/odd input.
    if ( |h| < 10 || |h| > 2 * max_frame_bytes || |h| % 2 != 0 || ! (/^[0-9a-fA-F]+$/ in h) )
        { ++structure_rejected; return f; }
    local b = hexstr_to_bytestring(h);
    f$length = |b|;
    f$kind = bytestring_to_count(b[2:3]);
    f$sid = to_lower(h[6:10]);
    if ( f$kind == 3 )
        {
        # packet.h/c: INIT=0, flags=0 for this profile, 64-byte P-256 X||Y.
        if ( |b| != 73 || b[5:9] != "\x00\x00\x00\x00" )
            { ++structure_rejected; return f; }
        local x = to_lower(h[18:82]);
        local y = to_lower(h[82:146]);
        local prime = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        # Cheap shape/range checks only, deliberately not an EC point check.
        if ( /^0+$/ in x || /^0+$/ in y || strcmp(x,prime) >= 0 || strcmp(y,prime) >= 0 )
            { ++structure_rejected; return f; }
        f$key_hash = sha256_hash(b[9:73]);
        }
    else if ( f$kind == 0 || f$kind == 1 )
        {
        # Clear header(5), truncated MAC(6), nonce(2), encrypted seq/options
        # or seq/ACK(4). Those last fields are NOT decoded or authenticated.
        if ( |b| < 17 ) { ++structure_rejected; return f; }
        }
    else if ( f$kind == 2 )
        {
        # FIN includes at least an encrypted terminating NUL after MAC/nonce.
        if ( |b| < 14 ) { ++structure_rejected; return f; }
        }
    else { ++structure_rejected; return f; }
    f$valid = T;
    ++valid_frames;
    return f;
    }

function candidates(query: string): Frames
    {
    local out: Frames = vector();
    if ( |query| > max_name_bytes ) { ++structure_rejected; return out; }
    if ( starts_with(query,"dnscat.") )
        {
        ++boundary_attempts;
        local tag = parse_hex(gsub(query[7:],/\./,""));
        if ( tag$valid ) { tag$suffix = "@tag:dnscat"; out[|out|] = tag; }
        return out;
        }
    local labels = split_string(query,/\./);
    local h = "";
    local consumed: count = 0;
    local tried: count = 0;
    for ( i in labels )
        {
        if ( i + 1 >= |labels| || tried >= max_boundaries ) break;
        if ( ! (/^[0-9a-fA-F]+$/ in labels[i]) ) break;
        h += labels[i];
        consumed += |labels[i]| + 1;
        ++tried; ++boundary_attempts;
        local f = parse_hex(h);
        if ( f$valid ) { f$suffix = query[consumed:]; out[|out|] = f; }
        }
    return out;
    }


function context(o: Observation): string
    {
    # Typed server port includes transport; client port/UID are not logical ID.
    return fmt("%s|%s|%s|%s|%s|%s",o$scope,o$peers$orig_h,o$peers$resp_h,o$peers$resp_p,o$request$suffix,o$request$sid);
    }
function admit_observation(o: Observation): Frame
    {
    local f = o$request;
    f$context = context(o);
    local empty: Frame;
    if ( f$context in sessions && o$at - sessions[f$context]$touched >= session_ttl )
        { delete sessions[f$context]; ++session_expiry; }
    if ( f$context in candidate_states && o$at - candidate_states[f$context]$at >= candidate_ttl )
        { remove_candidate(f$context); ++candidate_expiry; }
    if ( f$context in sessions )
        {
        local active = sessions[f$context];
        if ( active$closed || (f$kind == 3 && active$client_key != f$key_hash) )
            { ++pairing_rejected; return empty; }
        f$progressed = T;
        f$generation = active$generation;
        f$initial_key_hash = active$client_key;
        return f;
        }
    if ( f$kind == 3 )
        {
        # A new unanswered key revokes the old epoch even before timeout. Old
        # pending facts retain their old binding; they cannot resurrect it.
        if ( f$context in candidate_states && candidate_states[f$context]$client_key != f$key_hash )
            { remove_candidate(f$context); ++candidate_replacements; }
        if ( f$context !in candidate_states )
            {
            if ( max_candidates == 0 ) { ++coverage_degraded; return empty; }
            if ( |candidate_states| >= max_candidates )
                { remove_candidate(candidate_head); ++candidate_evictions; ++coverage_degraded; }
            ++next_generation; ++candidate_admissions;
            local s: Session = [$generation=next_generation,$at=o$at,$touched=o$at,$client_key=f$key_hash,$prev_link=candidate_tail];
            if ( candidate_tail != "" ) candidate_states[candidate_tail]$next_link = f$context;
            else candidate_head = f$context;
            candidate_tail = f$context;
            candidate_states[f$context] = s;
            if ( |candidate_states| > peak_candidates ) peak_candidates = |candidate_states|;
            }
        }
    if ( f$context !in candidate_states ) return empty;
    f$generation = candidate_states[f$context]$generation;
    f$initial_key_hash = candidate_states[f$context]$client_key;
    return f;
    }
function promote(k: string, s: Session): bool
    {
    if ( |sessions| >= max_sessions )
        {
        # Scan only on reply-backed promotion pressure, never per INIT admission.
        local oldest = "";
        local oldest_at = lifecycle_time();
        for ( key in sessions )
            if ( (sessions[key]$done || sessions[key]$closed) && sessions[key]$touched <= oldest_at )
                { oldest = key; oldest_at = sessions[key]$touched; }
        if ( oldest != "" ) { delete sessions[oldest]; ++tombstone_evictions; ++coverage_degraded; }
        else { ++session_overflow; ++coverage_degraded; return F; }
        }
    if ( max_sessions == 0 ) { ++session_overflow; ++coverage_degraded; return F; }
    remove_candidate(k);
    s$prev_link = ""; s$next_link = "";
    sessions[k] = s;
    ++session_admissions;
    if ( |sessions| > peak_sessions ) peak_sessions = |sessions|;
    return T;
    }
function paired_observation(o: Observation)
    {
    local q = o$request;
    local r = o$reply;
    local s: Session;
    local progressed = q$context in sessions;
    if ( progressed ) s = sessions[q$context];
    else if ( q$context in candidate_states ) s = candidate_states[q$context];
    else { ++pairing_rejected; ++epoch_rejected; return; }
    # Fence ALL kinds and idle updates across candidate removal/replacement and
    # promotion. A paired echo question is never a substitute for this evidence.
    if ( q$generation != s$generation || q$initial_key_hash != s$client_key )
        { ++pairing_rejected; ++epoch_rejected; return; }
    if ( (progressed && o$reply_at - s$touched >= session_ttl) || (! progressed && o$reply_at - s$at >= candidate_ttl) )
        { ++pairing_rejected; ++epoch_rejected; return; }
    if ( r$sid != q$sid ) { ++pairing_rejected; return; }
    if ( q$kind == 3 && r$kind == 3 )
        {
        if ( q$key_hash == r$key_hash || (s$server_key != "" && s$server_key != r$key_hash) )
            { ++pairing_rejected; return; }
        s$server_key = r$key_hash; s$enc = T;
        }
    else if ( q$kind == 0 && r$kind == 0 )
        {
        if ( ! s$syn || o$at < s$syn_at ) s$syn_at = o$at;
        s$syn = T;
        }
    else if ( q$kind == 1 && r$kind == 1 )
        {
        if ( ! s$msg || o$at > s$msg_at ) s$msg_at = o$at;
        s$msg = T;
        }
    else if ( r$kind == 2 && (q$kind == 1 || q$kind == 2) )
        { if ( ! s$closed ) ++fins; s$closed = T; }
    else { ++pairing_rejected; return; }
    s$touched = o$reply_at;
    if ( ! progressed && s$enc )
        {
        if ( ! promote(q$context,s) ) return;
        progressed = T;
        }
    if ( progressed )
        {
        if ( ! s$done && ! s$closed && s$enc && s$syn && s$msg && s$at <= s$syn_at && s$syn_at <= s$msg_at )
            {
            s$done = T; ++notices;
            NOTICE([$note=CompatibleSession,$ts=o$reply_at,$id=o$peers,$uid=o$uid,
                $msg="dnscat2 DNS session pattern observed: paired negotiation and session-start messages followed by two-way session traffic",
                $sub=fmt("evidence=ENC_INIT,SYN,MSG; peer_keys=distinct; dns_request_reply=matched; suffix=%s; sid=%s",q$suffix,q$sid),$identifier=q$context,$suppress_for=0sec]);
            }
        sessions[q$context] = s;
        }
    else candidate_states[q$context] = s;
    }
function local_dispatch(o: Observation): Frame
    {
    sweep();
    if ( ! o?$reply ) return admit_observation(o);
    paired_observation(o);
    local empty: Frame;
    return empty;
    }
redef dispatch_observation = local_dispatch;
function token(c: connection, msg: dns_msg): string
    { return fmt("%s|%d",c$uid,msg$id); }
function identity(c: connection, msg: dns_msg, ans: dns_answer): bool
    {
    local k = token(c,msg);
    if ( ! c$dnc_message_ok || ! msg$QR || k !in pending ) return F;
    local p = pending[k];
    if ( network_time() - p$at >= pending_ttl )
        { remove_pending(k); ++pending_expiry; return F; }
    if ( ! p$question_ok || ans$answer_type != DNS_ANS || ans$qclass != 1 || ans$qtype != p$qtype || sha256_hash(to_lower(ans$query)) != p$question_hash )
        { pending[k]$invalid_response = T; ++pairing_rejected; return F; }
    return ! p$invalid_response;
    }
function deliver(k: string, q: Frame, r: Frame)
    {
    if ( ! r$valid ) { ++pairing_rejected; return; }
    local p = pending[k];
    local o: Observation = [$peers=p$peers,$uid=p$uid,$token=p$observation_token,$dns_id=p$dns_id,$serial=p$serial,$scope=observation_scope,$at=p$at,$qtype=p$qtype,$question_hash=p$question_hash,$request=q,$reply=r,$reply_at=network_time()];
    dispatch_observation(o);
    }
function answer(c: connection, msg: dns_msg, ans: dns_answer, data: string, is_txt: bool)
    {
    if ( ! identity(c,msg,ans) ) return;
    local k = token(c,msg);
    local p = pending[k];
    if ( |data| > 2*max_frame_bytes+max_name_bytes+16 ) { ++structure_rejected; return; }
    for ( i in p$frames )
        {
        local q = p$frames[i];
        local h = to_lower(data);
        if ( ! is_txt )
            {
            if ( |h| > max_name_bytes ) { ++structure_rejected; next; }
            if ( q$suffix == "@tag:dnscat" )
                {
                if ( ! starts_with(h,"dnscat.") ) { ++pairing_rejected; next; }
                h = h[7:];
                }
            else
                {
                if ( ! ends_with(h,cat(".",q$suffix)) ) { ++pairing_rejected; next; }
                h = h[0:|h|-|q$suffix|-1];
                }
            h = gsub(h,/\./,"");
            }
        deliver(k,q,parse_hex(h));
        }
    }
function address_block(c: connection, msg: dns_msg, ans: dns_answer, a: addr, width: count)
    {
    if ( ! identity(c,msg,ans) ) return;
    local k = token(c,msg);
    local p = pending[k];
    local cap: count = 64;
    if ( width == 16 ) cap = 16;
    ++p$rr_count;
    if ( p$rr_count > cap ) { p$invalid_response = T; ++address_rejected; pending[k] = p; return; }
    # BIF host-order 32-bit words, not rendered address text. RR type fixes width.
    local words = addr_to_counts(a);
    local h = "";
    if ( width == 4 && |words| == 1 ) h = fmt("%08x",words[0]);
    else if ( width == 16 && |words| == 4 )
        for ( i in words ) h += fmt("%08x",words[i]);
    else if ( width == 16 && |words| == 1 )
        h = cat("00000000000000000000ffff",fmt("%08x",words[0]));
    else { p$invalid_response = T; ++address_rejected; pending[k] = p; return; }
    local b = hexstr_to_bytestring(h);
    local seq = bytestring_to_count(b[0:1]);
    local block = b[1:];
    if ( seq in p$blocks )
        {
        if ( p$blocks[seq] != block ) { p$invalid_response = T; ++address_rejected; }
        else ++address_duplicates;
        }
    else p$blocks[seq] = block;
    pending[k] = p;
    }
function finish_address(k: string)
    {
    local p = pending[k];
    local cap: count = 64;
    local width: count = 3;
    if ( p$qtype == 28 ) { cap = 16; width = 15; }
    if ( p$invalid_response || |p$blocks| == 0 ) { ++address_rejected; return; }
    local first: count = 255;
    for ( seq in p$blocks ) if ( seq < first ) first = seq;
    if ( first == 0 || first > 255-cap-1 ) { ++address_rejected; return; }
    local raw = "";
    local n: count = 0;
    while ( n < |p$blocks| )
        {
        if ( first+n !in p$blocks || first+n > 253 ) { ++address_rejected; return; }
        raw += p$blocks[first+n]; ++n;
        }
    local length = bytestring_to_count(raw[0:1]);
    if ( length > cap*width-1 || length > max_frame_bytes || length+1 > |raw| || |raw|-length-1 >= width )
        { ++address_rejected; return; }
    # v0.07 protocol and client driver ignore padding values. Validate only the
    # declared length and less-than-one-block padding amount above, then trim.
    # The pinned Ruby encoder happens to use FF, but that is not a receiver rule.
    local r = parse_hex(bytestring_to_hexstr(raw[1:length+1]));
    for ( i in p$frames ) deliver(k,p$frames[i],r);
    }

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    sweep();
    c$dnc_message_ok = msg$opcode == 0 && msg$rcode == 0 && ! msg$TC && msg$num_queries == 1 && ((is_orig && ! msg$QR) || (! is_orig && msg$QR));
    local k = token(c,msg);
    if ( msg$QR && k in pending )
        {
        pending[k]$question_ok = F;
        pending[k]$invalid_response = F;
        pending[k]$blocks = table(); pending[k]$rr_count = 0;
        }
    }
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    ++queries;
    if ( ! c$dnc_message_ok || qclass != 1 || (qtype != 16 && qtype != 5 && qtype != 15 && qtype != 1 && qtype != 28) ) return;
    local k = token(c,msg);
    local qhash = sha256_hash(query);
    if ( k in pending )
        {
        if ( network_time() - pending[k]$at >= pending_ttl ) { remove_pending(k); ++pending_expiry; }
        else if ( pending[k]$question_hash == qhash && pending[k]$qtype == qtype ) { ++retries; return; }
        else { remove_pending(k); ++pairing_rejected; }
        }
    ++transaction_serial;
    local observation_token = fmt("%s|%d",k,transaction_serial);
    local fs: Frames = vector();
    local normalized = candidates(query);
    local progressed = F;
    for ( i in normalized )
        {
        local o: Observation = [$peers=c$id,$uid=c$uid,$token=observation_token,$dns_id=msg$id,$serial=transaction_serial,$scope=observation_scope,$at=network_time(),$qtype=qtype,$question_hash=qhash,$request=normalized[i]];
        local f = dispatch_observation(o);
        if ( f$valid ) { fs[|fs|] = f; if ( f$progressed ) progressed = T; }
        }
    # Alternative hex-label boundaries are candidates, not failed pairings. Count
    # missing request context only when none of the normalized choices was admitted.
    if ( |fs| == 0 ) { if ( |normalized| > 0 ) ++pairing_rejected; return; }
    if ( |pending| >= max_pending )
        {
        if ( pending_head != "" ) { remove_pending(pending_head); ++pending_evictions; ++coverage_degraded; }
        else { ++pending_overflow; ++coverage_degraded; return; }
        }
    if ( max_pending == 0 ) { ++pending_overflow; ++coverage_degraded; return; }
    local p: Pending = [$at=network_time(),$peers=c$id,$uid=c$uid,$observation_token=observation_token,$dns_id=msg$id,$serial=transaction_serial,$question_hash=qhash,$qtype=qtype,$frames=fs,$queued=!progressed];
    if ( ! progressed )
        {
        p$prev_link = pending_tail;
        if ( pending_tail != "" ) pending[pending_tail]$next_link = k;
        else pending_head = k;
        pending_tail = k;
        }
    pending[k] = p; ++pending_admissions;
    if ( |pending| > peak_pending ) peak_pending = |pending|;
    }
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local k = token(c,msg);
    if ( k !in pending ) return;
    pending[k]$question_ok = c$dnc_message_ok && qclass == 1 && qtype == pending[k]$qtype && sha256_hash(to_lower(query)) == pending[k]$question_hash;
    if ( ! pending[k]$question_ok ) { pending[k]$invalid_response = T; ++pairing_rejected; }
    }
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
    {
    if ( token(c,msg) !in pending ) return;
    local n: count = 0;
    for ( i in strs ) { n += |strs[i]|; if ( n > 2*max_frame_bytes ) { ++structure_rejected; return; } }
    answer(c,msg,ans,join_string_vec(strs,""),T);
    }
event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    { answer(c,msg,ans,name,F); }
event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count)
    { answer(c,msg,ans,name,F); }
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    { address_block(c,msg,ans,a,4); }
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    { address_block(c,msg,ans,a,16); }
event dns_end(c: connection, msg: dns_msg)
    {
    local k = token(c,msg);
    if ( msg$QR && k in pending )
        {
        if ( pending[k]$qtype == 1 || pending[k]$qtype == 28 ) finish_address(k);
        remove_pending(k);
        }
    }
event zeek_done()
    {
    local cq: count = 0;
    local pq: count = 0;
    local queue_errors: count = 0;
    local current = candidate_head;
    local previous = "";
    while ( current != "" && cq <= |candidate_states| )
        {
        if ( current !in candidate_states ) { ++queue_errors; break; }
        if ( candidate_states[current]$prev_link != previous ) ++queue_errors;
        previous = current; current = candidate_states[current]$next_link; ++cq;
        }
    if ( current != "" || cq != |candidate_states| || previous != candidate_tail ) ++queue_errors;
    current = pending_head; previous = "";
    while ( current != "" && pq <= |pending| )
        {
        if ( current !in pending ) { ++queue_errors; break; }
        if ( ! pending[current]$queued || pending[current]$prev_link != previous ) ++queue_errors;
        previous = current; current = pending[current]$next_link; ++pq;
        }
    local expected: count = 0;
    for ( key in pending ) if ( pending[key]$queued ) ++expected;
    if ( current != "" || pq != expected || previous != pending_tail ) ++queue_errors;
    print fmt("{\"module\":\"DNScat2\",\"queries\":%d,\"boundary_attempts\":%d,\"valid_frames\":%d,\"structure_rejected\":%d,\"pairing_rejected\":%d,\"pending_admissions\":%d,\"candidate_admissions\":%d,\"session_admissions\":%d,\"pending_overflow\":%d,\"session_overflow\":%d,\"pending_expiry\":%d,\"candidate_expiry\":%d,\"session_expiry\":%d,\"candidate_evictions\":%d,\"pending_evictions\":%d,\"tombstone_evictions\":%d,\"candidate_replacements\":%d,\"epoch_rejected\":%d,\"coverage_degraded\":%d,\"retries\":%d,\"notices\":%d,\"fins\":%d,\"address_rejected\":%d,\"address_duplicates\":%d,\"pending\":%d,\"candidates\":%d,\"sessions\":%d,\"peak_pending\":%d,\"peak_candidates\":%d,\"peak_sessions\":%d,\"limit_pending\":%d,\"limit_candidates\":%d,\"limit_sessions\":%d,\"candidate_queue\":%d,\"pending_queue\":%d,\"queue_errors\":%d}",queries,boundary_attempts,valid_frames,structure_rejected,pairing_rejected,pending_admissions,candidate_admissions,session_admissions,pending_overflow,session_overflow,pending_expiry,candidate_expiry,session_expiry,candidate_evictions,pending_evictions,tombstone_evictions,candidate_replacements,epoch_rejected,coverage_degraded,retries,notices,fins,address_rejected,address_duplicates,|pending|,|candidate_states|,|sessions|,peak_pending,peak_candidates,peak_sessions,max_pending,max_candidates,max_sessions,cq,pq,queue_errors);
    }
