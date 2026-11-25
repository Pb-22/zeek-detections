# Optional Zeek 9.0.1 finite-input native Broker adapter. Never loaded by main.
@load base/frameworks/cluster
@load policy/frameworks/cluster/backend/broker
@load ./main
redef exit_only_after_terminate = T;
redef Log::default_rotation_interval = 0secs;
redef Log::default_rotation_postprocessor_cmd = "";
redef LogAscii::use_json = T;
# Workers retain DNS normalization locally; do not let stock remote log filters
# turn this metadata adapter into a raw DNS/connection-log centralizer.
redef Log::enable_remote_logging = F;
module DNCCluster;
export {
    const finite_mode = F &redef;
    const max_worker_facts = 2048 &redef;
    const max_owner_facts = 4096 &redef;
    const max_tokens = 4096 &redef;
    const expected_workers: set[string] = { "worker-0", "worker-1" } &redef;
    const expected_owners: set[string] = { "proxy-0", "proxy-1" } &redef;
    const allowed_scopes: set[string] = { "site-1", "scope-a", "scope-b", "local" } &redef;
    const expected_packets: count = 0 &redef;
    const input_hash = "" &redef;
    # Operational transport scheduling only; never a source watermark.
    const sequential_sources = F &redef;
    type Input: record {
        packets: count;
        hash: string;
        has_data: bool;
        first: time;
        last: time;
    };
    const assigned_inputs: table[string] of Input = table() &redef;
    type View: record {
        id: string;
        nodes: table[string] of string;
        inputs: table[string] of Input;
    };
    type Key: record {
        schema_version: count &default=1;
        scope: string;
        client: addr;
        server: addr;
        server_port: port;
        wrapper: string;
        suffix: string;
        sid: string;
    };
    type Fact: record {
        key: Key;
        worker: string;
        incarnation: string;
        view_id: string;
        owner_topic: string;
        owner_incarnation: string;
        seq: count;
        # Broker time_point conversion can round an epoch double by an ULP.
        # Native source seconds as doubles preserve the callback value exactly.
        query_seconds: double;
        event_seconds: double;
        token: string;
        o: DNScat2::Observation;
    };
    type Facts: vector of Fact;
    type EOS: record {
        worker: string;
        incarnation: string;
        view_id: string;
        owner: string;
        last_seq: count;
        packets: count;
        hash: string;
        has_observation: bool;
        first: time;
        last: time;
        complete: bool;
    };
    global after_eof: event();
    global fact: event(f: Fact);
    global eos: event(e: EOS);
    global install_view: event(v: View);
    global ready_ack: event(node: string, incarnation: string, view_id: string);
    global start_source: event(worker: string, view_id: string);
    global fact_ack: event(owner: string, seq: count, accepted: bool);
    global eos_ack: event(owner: string, last_seq: count);
    global ack_seen: event(worker: string, incarnation: string, owner: string, seq: count, is_eos: bool);
    global prepared: event(owner: string, incarnation: string, view_id: string, complete: bool, n: count);
    global commit_window: event(view_id: string);
    global owner_done: event(owner: string, incarnation: string, view_id: string, n: count);
    global failure: event(node: string, view_id: string, reason: string);
    global finish: event();
    global publish_fact: function(f: Fact): bool &redef;
    global publication_order: function(f: Facts): Facts &redef;
}
type Trace: record {
    action: string;
    node: string &default=Cluster::node;
    worker: string &default="";
    owner: string &default="";
    token: string &default="";
    view_id: string &default="";
    seq: count &default=0;
    packets: count &default=0;
    facts: count &default=0;
    complete: bool &default=F;
    has_observation: bool &default=F;
    observed: time &default=double_to_time(0);
    source_query: time &default=double_to_time(0);
    uid: string &default="";
    scope: string &default="";
    sid: string &default="";
    kind: string &default="";
    frame_kind: count &default=255;
    reply_kind: count &default=255;
    route: string &default="";
    generation: count &default=0;
    detail: string &default="";
    exact_time: string &default="";
    local_network: time &default=network_time();
};
function trace(t: Trace) { print to_json(t); }
global view: View;
global installed = F;
global bad = F;
# Bound operational failure publication too, not only observation buffers.
global failure_sent = F;
global finished = F;
global view_sent = F;
global current_nodes: table[string] of string;
global view_ready: set[string];
global packets: count = 0;
global source_first = double_to_time(0);
global source_last = double_to_time(0);
global source_eof = F;
global source_dropped: count = 0;
global worker1_released = F;
global sealed = F;
global started = F;
global sent = F;
global source_buffer: vector of DNScat2::Observation;
global seq_count: table[string] of count &default=0;
global ack_counts: table[string] of count &default=0;
global eos_seen: table[string] of EOS;
global received: table[string] of count &default=0;
global transport_hash: table[string,count] of string;
global facts: Facts;
global owner_prepared = F;
global owner_committed = F;
global token_bindings: table[Key,string] of DNScat2::Frame;
global fact_identity: table[Key,string,bool] of string;
global source_clock = double_to_time(0);
global prepare_votes: table[string] of bool;
global prepare_counts: table[string] of count;
global global_fact_acks: set[string,string,count];
global global_eos_acks: set[string,string];
global done_owners: set[string];
global decision_sent = F;
global shutdown_scheduled = F;

function event_time(o: DNScat2::Observation): time
    { if ( o?$reply ) return o$reply_at; return o$at; }
function observation_digest(o: DNScat2::Observation): string
    {
    # to_json renders time with display precision; bind full native time values
    # too, so a conflicting sub-microsecond payload is not a false duplicate.
    return sha256_hash(cat(to_json(o),fmt("/%.17g/%.17g",time_to_double(o$at),o?$reply ? time_to_double(o$reply_at) : 0.0)));
    }
function key_for(o: DNScat2::Observation): Key
    {
    return [$scope=o$scope,$client=o$peers$orig_h,$server=o$peers$resp_h,$server_port=o$peers$resp_p,
        $wrapper=starts_with(o$request$suffix,"@tag:") ? "tag" : "domain",$suffix=o$request$suffix,$sid=o$request$sid];
    }
function remote_dispatch(o: DNScat2::Observation): DNScat2::Frame
    {
    local empty: DNScat2::Frame;
    if ( Cluster::local_node_type()!=Cluster::WORKER || ! finite_mode ) return empty;
    if ( sealed || |source_buffer|>=max_worker_facts )
        {
        ++source_dropped;
        if ( ! bad ) trace([$action="SOURCE_INCOMPLETE",$worker=Cluster::node,$detail="late fact or bounded source buffer overflow"]);
        bad=T;
        if ( installed && ! failure_sent )
            { failure_sent=T; Cluster::publish(Cluster::manager_topic,failure,Cluster::node,view$id,"late fact/buffer overflow"); }
        return empty;
        }
    # No local lifecycle and no worker epoch: even a SYN/MSG without local INIT
    # retains native transaction pairing and can reach its stable owner.
    o$request$generation=0; o$request$initial_key_hash=""; o$request$context=""; o$request$progressed=F;
    source_buffer[|source_buffer|]=o;
    trace([$action="SOURCE_FACT",$worker=Cluster::node,$token=o$token,$observed=event_time(o),$source_query=o$at,$uid=o$uid,$scope=o$scope,$sid=o$request$sid,$kind=o?$reply ? "PAIR" : "QUERY",$frame_kind=o$request$kind,$reply_kind=o?$reply ? o$reply$kind : 255,$exact_time=fmt("%.17g",time_to_double(event_time(o)))]);
    if ( ! o?$reply ) return o$request;
    return empty;
    }
function owner_clock(): time
    { if ( Cluster::local_node_type()==Cluster::PROXY ) return source_clock; return network_time(); }
redef DNScat2::dispatch_observation = remote_dispatch;
redef DNScat2::lifecycle_time = owner_clock;

function native_publish(f: Fact): bool
    { return Cluster::publish_hrw(Cluster::proxy_pool,f$key,fact,f); }
function native_order(f: Facts): Facts { return f; }
redef publish_fact = native_publish;
redef publication_order = native_order;

function mark_bad(reason: string)
    {
    bad=T;
    trace([$action="INCOMPLETE",$detail=reason]);
    if ( installed && ! failure_sent && Cluster::local_node_type()!=Cluster::MANAGER )
        { failure_sent=T; Cluster::publish(Cluster::manager_topic,failure,Cluster::node,view$id,reason); }
    }
function worker_maybe_send()
    {
    if ( ! finite_mode || Cluster::local_node_type()!=Cluster::WORKER || ! installed || ! started || ! sealed || sent ) return;
    if ( Cluster::proxy_pool$alive_count!=|expected_owners| ) { mark_bad("routing view unavailable"); return; }
    for ( owner in expected_owners )
        if ( owner !in current_nodes || current_nodes[owner]!=view$nodes[owner] ) { mark_bad("routing incarnation changed"); return; }
    sent=T;
    local outgoing: Facts = vector();
    for ( i in source_buffer )
        {
        local o=source_buffer[i];
        local k=key_for(o);
        local topic=Cluster::hrw_topic(Cluster::proxy_pool,k);
        local owner_name="";
        for ( own in expected_owners ) if ( topic==Cluster::node_topic(own) ) owner_name=own;
        if ( owner_name=="" ) { mark_bad("unknown HRW owner"); return; }
        ++seq_count[owner_name];
        local f: Fact=[$key=k,$worker=Cluster::node,$incarnation=Cluster::node_id(),$view_id=view$id,
            $owner_topic=topic,$owner_incarnation=view$nodes[owner_name],$seq=seq_count[owner_name],
            $query_seconds=time_to_double(o$at),$event_seconds=time_to_double(event_time(o)),
            $token=fmt("%s/%s/%s/%d/%d",Cluster::node,Cluster::node_id(),o$uid,o$dns_id,o$serial),$o=o];
        outgoing[|outgoing|]=f;
        }
    outgoing=publication_order(outgoing);
    for ( j in outgoing )
        {
        local send=outgoing[j];
        local ok=publish_fact(send);
        trace([$action="FACT_SEND",$worker=Cluster::node,$owner=send$owner_topic,$seq=send$seq,$token=send$token,$observed=event_time(send$o),$source_query=send$o$at,$uid=send$o$uid,$scope=send$o$scope,$sid=send$key$sid,$kind=send$o?$reply ? "PAIR" : "QUERY",$complete=ok]);
        if ( ! ok ) bad=T;
        }
    for ( owner2 in expected_owners )
        {
        local e: EOS=[$worker=Cluster::node,$incarnation=Cluster::node_id(),$view_id=view$id,$owner=owner2,$last_seq=seq_count[owner2],
            $packets=packets,$hash=input_hash,$has_observation=packets>0,$first=source_first,$last=source_last,$complete=source_eof && ! bad && packets==expected_packets];
        local ok2=Cluster::publish(Cluster::node_topic(owner2),eos,e);
        trace([$action="EOS_SEND",$worker=Cluster::node,$owner=owner2,$seq=e$last_seq,$packets=packets,$observed=source_last,$has_observation=packets>0,$complete=e$complete && ok2]);
        }
    }
function manager_maybe_decide()
    {
    if ( Cluster::local_node_type()!=Cluster::MANAGER || decision_sent || |prepare_votes|!=|expected_owners| || |global_eos_acks|!=|expected_workers|*|expected_owners| ) return;
    local expected: count=0;
    local complete=!bad;
    for ( owner in prepare_votes ) { expected+=prepare_counts[owner]; if ( ! prepare_votes[owner] ) complete=F; }
    if ( |global_fact_acks|<expected ) return;
    decision_sent=T;
    if ( ! complete )
        {
        trace([$action="WINDOW_INCOMPLETE",$complete=F,$facts=expected]);
        shutdown_scheduled=T; schedule 1sec { finish() }; return;
        }
    trace([$action="WINDOW_COMMIT",$complete=T,$facts=expected]);
    Cluster::publish(Cluster::proxy_topic,commit_window,view$id);
    }
function compare_facts(a: Fact,b: Fact): int
    {
    local ta=event_time(a$o); local tb=event_time(b$o);
    if ( ta<tb ) return -1;
    if ( ta>tb ) return 1;
    # Query facts precede paired facts; INIT queries precede other queries at a
    # tied source time. Conflicting INIT ties are rejected before any reduction.
    if ( ! a$o?$reply && b$o?$reply ) return -1;
    if ( a$o?$reply && ! b$o?$reply ) return 1;
    if ( ! a$o?$reply && a$o$request$kind==3 && b$o$request$kind!=3 ) return -1;
    if ( ! b$o?$reply && b$o$request$kind==3 && a$o$request$kind!=3 ) return 1;
    return strcmp(a$token,b$token);
    }
function owner_maybe_prepare()
    {
    if ( owner_prepared || |eos_seen|!=|expected_workers| ) return;
    owner_prepared=T;
    for ( worker in expected_workers )
        {
        local e=eos_seen[worker];
        if ( ! e$complete || e$last_seq!=received[worker] ) bad=T;
        local seq: count=1;
        while ( seq<=e$last_seq && seq<=max_owner_facts )
            { if ( [worker,seq] !in transport_hash ) bad=T; ++seq; }
        }
    # Validate same-key/source-time conflicting key changes for the whole
    # closed window before any Notice can be emitted.
    local barriers: table[Key,time] of string;
    for ( i in facts )
        {
        local f=facts[i];
        if ( ! f$o?$reply && f$o$request$kind==3 )
            {
            if ( [f$key,f$o$at] in barriers && barriers[f$key,f$o$at]!=f$o$request$key_hash ) bad=T;
            else barriers[f$key,f$o$at]=f$o$request$key_hash;
            }
        }
    # All semantic conflicts/capacity are checked before the manager can commit;
    # finding one only midway through reduction could follow an earlier Notice.
    local semantics: table[Key,string,bool] of string;
    local queries: table[Key,string] of DNScat2::Observation;
    for ( si in facts )
        {
        local sf=facts[si];
        local paired=sf$o?$reply;
        local hash=observation_digest(sf$o);
        if ( [sf$key,sf$token,paired] in semantics && semantics[sf$key,sf$token,paired]!=hash ) bad=T;
        else semantics[sf$key,sf$token,paired]=hash;
        if ( ! paired ) queries[sf$key,sf$token]=sf$o;
        }
    if ( |queries|>max_tokens || |semantics|>max_owner_facts ) bad=T;
    for ( pi in facts )
        {
        local pf=facts[pi];
        if ( ! pf$o?$reply ) next;
        if ( [pf$key,pf$token] !in queries ) { bad=T; next; }
        local qo=queries[pf$key,pf$token];
        if ( to_json(qo$request)!=to_json(pf$o$request) || qo$at!=pf$o$at || qo$uid!=pf$o$uid || qo$dns_id!=pf$o$dns_id || qo$serial!=pf$o$serial || qo$qtype!=pf$o$qtype || qo$question_hash!=pf$o$question_hash || to_json(qo$peers)!=to_json(pf$o$peers) ) bad=T;
        }
    trace([$action="PREPARED",$owner=Cluster::node,$complete=!bad,$facts=|facts|]);
    Cluster::publish(Cluster::manager_topic,prepared,Cluster::node,Cluster::node_id(),view$id,!bad,|facts|);
    }
function validate_fact(f: Fact): bool
    {
    if ( ! installed || f$view_id!=view$id || f$worker !in expected_workers || f$incarnation!=view$nodes[f$worker] || f$owner_topic!=Cluster::node_topic(Cluster::node) || f$owner_incarnation!=Cluster::node_id() ) return F;
    local o=f$o; local q=o$request;
    if ( o$scope !in allowed_scopes || |o$scope|>128 || |o$uid|>128 || |o$token|>256 || |f$token|>512 || |q$suffix|==0 || |q$suffix|>253 || |q$key_hash|>64 || |q$context|>0 || q$generation!=0 || |q$initial_key_hash|>0 ) return F;
    if ( ! q$valid || ! (/^[0-9a-f]{4}$/ in q$sid) || q$kind>3 || q$length<5 || q$length>DNScat2::max_frame_bytes || o$dns_id>65535 || o$serial==0 || f$seq==0 || f$seq>max_owner_facts ) return F;
    if ( f$token!=fmt("%s/%s/%s/%d/%d",f$worker,f$incarnation,o$uid,o$dns_id,o$serial) ) return F;
    if ( ! (/^[0-9a-f]{64}$/ in o$question_hash) ) return F;
    if ( to_json(f$key)!=to_json(key_for(o)) ) return F;
    local input=view$inputs[f$worker];
    # This one-microsecond check is only the classic PCAP representation bound,
    # never a lateness/watermark lag. EOS/contiguous streams prove completeness.
    local lo=time_to_double(input$first)-0.000001;
    local hi=time_to_double(input$last)+0.000001;
    if ( ! input$has_data || ! (f$query_seconds>=lo && f$query_seconds<=hi && f$event_seconds>=f$query_seconds && f$event_seconds<=hi) ) return F;
    if ( ! o?$reply && f$query_seconds!=f$event_seconds ) return F;
    if ( o?$reply && (! o?$reply_at || ! o$reply$valid || |o$reply$key_hash|>64 || o$reply$kind>3 || o$reply$length>DNScat2::max_frame_bytes) ) return F;
    return T;
    }

event raw_packet(h: raw_pkt_hdr)
    {
    if ( ! finite_mode || Cluster::local_node_type()!=Cluster::WORKER ) return;
    ++packets;
    if ( packets==1 ) source_first=network_time();
    source_last=network_time();
    }
event Pcap::file_done(path: string)
    {
    if ( ! finite_mode || Cluster::local_node_type()!=Cluster::WORKER || source_eof ) return;
    if ( is_remote_event() || path!="/input/source.pcap" || ! reading_traces() || finished ) { mark_bad("invalid native source close"); return; }
    source_eof=T;
    if ( packets!=expected_packets || |input_hash|!=64 ) bad=T;
    trace([$action="NATIVE_EOF",$worker=Cluster::node,$packets=packets,$facts=|source_buffer|,$observed=source_last,$has_observation=packets>0,$complete=!bad]);
    event after_eof();
    }
event after_eof() { sealed=T; worker_maybe_send(); }
event Cluster::node_up(name: string,id: string)
    {
    if ( ! finite_mode ) return;
    if ( installed && name in view$nodes && view$nodes[name]!=id ) { mark_bad("membership incarnation changed"); return; }
    if ( name !in expected_workers && name !in expected_owners && name!="manager" ) { mark_bad("unconfigured member"); return; }
    current_nodes[name]=id;
    if ( Cluster::local_node_type()==Cluster::MANAGER && ! view_sent && Cluster::get_active_node_count(Cluster::WORKER)==|expected_workers| && Cluster::get_active_node_count(Cluster::PROXY)==|expected_owners| )
        {
        if ( |assigned_inputs|!=|expected_workers| ) { mark_bad("missing fixed input assignments"); return; }
        view_sent=T;
        local ids: table[string] of string;
        for ( w in expected_workers ) { if ( w !in current_nodes ) return; ids[w]=current_nodes[w]; }
        for ( p in expected_owners ) { if ( p !in current_nodes ) return; ids[p]=current_nodes[p]; }
        view=[$id=fmt("finite/%s",Cluster::node_id()),$nodes=ids,$inputs=assigned_inputs];
        installed=T;
        Cluster::publish(Cluster::worker_topic,install_view,view);
        Cluster::publish(Cluster::proxy_topic,install_view,view);
        trace([$action="VIEW_SENT",$view_id=view$id]);
        }
    }
event Cluster::node_down(name: string,id: string)
    {
    if ( finite_mode && installed && ! finished && name in view$nodes ) mark_bad("fixed membership went down");
    }
event install_view(v: View)
    {
    if ( ! finite_mode || installed ) return;
    if ( |v$nodes|!=|expected_workers|+|expected_owners| || |v$inputs|!=|expected_workers| || Cluster::node !in v$nodes || v$nodes[Cluster::node]!=Cluster::node_id() ) { mark_bad("invalid fixed view"); return; }
    for ( w in expected_workers ) if ( w !in v$nodes || w !in v$inputs || |v$inputs[w]$hash|!=64 ) { mark_bad("invalid source binding"); return; }
    view=v; installed=T;
    trace([$action="VIEW_INSTALLED",$view_id=view$id]);
    Cluster::publish(Cluster::manager_topic,ready_ack,Cluster::node,Cluster::node_id(),view$id);
    }
event ready_ack(node: string,incarnation: string,view_id: string)
    {
    if ( Cluster::local_node_type()!=Cluster::MANAGER || ! installed || view_id!=view$id || node !in view$nodes || incarnation!=view$nodes[node] ) return;
    add view_ready[node];
    if ( |view_ready|==|expected_workers|+|expected_owners| )
        {
        trace([$action="FIXED_VIEW_READY",$complete=T]);
        if ( sequential_sources ) Cluster::publish(Cluster::node_topic("worker-0"),start_source,"worker-0",view$id);
        else for ( w in expected_workers ) Cluster::publish(Cluster::node_topic(w),start_source,w,view$id);
        }
    }
event start_source(worker: string,view_id: string)
    {
    if ( Cluster::local_node_type()!=Cluster::WORKER || worker!=Cluster::node || ! installed || view_id!=view$id ) return;
    started=T; worker_maybe_send();
    }
event fact(f: Fact)
    {
    if ( Cluster::local_node_type()!=Cluster::PROXY ) return;
    if ( owner_prepared || ! validate_fact(f) ) { mark_bad("invalid/late fact"); return; }
    # Reconstitute the unchanged native source callback time, not the rounded
    # Broker timestamp representation and never owner wall/network time.
    f$o$at=double_to_time(f$query_seconds);
    if ( f$o?$reply ) f$o$reply_at=double_to_time(f$event_seconds);
    local digest=sha256_hash(cat(to_json(f),observation_digest(f$o)));
    if ( [f$worker,f$seq] in transport_hash )
        {
        if ( transport_hash[f$worker,f$seq]!=digest ) mark_bad("conflicting transport duplicate");
        trace([$action="FACT_DUPLICATE",$worker=f$worker,$owner=Cluster::node,$seq=f$seq,$token=f$token]);
        Cluster::publish(Cluster::node_topic(f$worker),fact_ack,Cluster::node,f$seq,!bad); return;
        }
    if ( |facts|>=max_owner_facts ) { mark_bad("bounded owner fact buffer overflow"); return; }
    transport_hash[f$worker,f$seq]=digest; ++received[f$worker]; facts[|facts|]=f;
    trace([$action="FACT_RX",$worker=f$worker,$owner=Cluster::node,$seq=f$seq,$token=f$token,$observed=event_time(f$o),$source_query=f$o$at,$uid=f$o$uid,$scope=f$o$scope,$sid=f$key$sid,$route=sha256_hash(to_json(f$key)),$kind=f$o?$reply ? "PAIR" : "QUERY",$frame_kind=f$o$request$kind,$reply_kind=f$o?$reply ? f$o$reply$kind : 255]);
    Cluster::publish(Cluster::node_topic(f$worker),fact_ack,Cluster::node,f$seq,T);
    }
event eos(e: EOS)
    {
    if ( Cluster::local_node_type()!=Cluster::PROXY || ! installed ) return;
    if ( e$worker !in expected_workers || e$incarnation!=view$nodes[e$worker] || e$view_id!=view$id || e$owner!=Cluster::node || e$last_seq>max_owner_facts ) { mark_bad("invalid EOS identity/bounds"); return; }
    if ( e$worker in eos_seen ) { if ( to_json(eos_seen[e$worker])!=to_json(e) ) mark_bad("conflicting EOS"); return; }
    local input=view$inputs[e$worker];
    if ( ! e$complete || e$hash!=input$hash || e$packets!=input$packets || e$has_observation!=input$has_data || e$first!=input$first || e$last!=input$last ) bad=T;
    eos_seen[e$worker]=e;
    trace([$action="EOS_RX",$worker=e$worker,$owner=Cluster::node,$seq=e$last_seq,$packets=e$packets,$observed=e$last,$has_observation=e$has_observation,$complete=!bad]);
    Cluster::publish(Cluster::node_topic(e$worker),eos_ack,Cluster::node,e$last_seq);
    owner_maybe_prepare();
    }
event fact_ack(owner: string,seq: count,accepted: bool)
    {
    trace([$action="ACK",$worker=Cluster::node,$owner=owner,$seq=seq,$complete=accepted]);
    Cluster::publish(Cluster::manager_topic,ack_seen,Cluster::node,Cluster::node_id(),owner,seq,F);
    }
event eos_ack(owner: string,last_seq: count)
    {
    trace([$action="EOS_ACK",$worker=Cluster::node,$owner=owner,$seq=last_seq,$complete=source_eof]);
    Cluster::publish(Cluster::manager_topic,ack_seen,Cluster::node,Cluster::node_id(),owner,last_seq,T);
    }
event ack_seen(worker: string,incarnation: string,owner: string,seq: count,is_eos: bool)
    {
    if ( Cluster::local_node_type()!=Cluster::MANAGER || ! installed || worker !in expected_workers || incarnation!=view$nodes[worker] || owner !in expected_owners ) return;
    if ( seq>max_owner_facts ) { bad=T; return; }
    if ( is_eos ) add global_eos_acks[worker,owner];
    else add global_fact_acks[worker,owner,seq];
    if ( sequential_sources && ! worker1_released && worker=="worker-0" && |global_eos_acks|>=2 )
        {
        # All worker-0 per-owner ACKs must precede releasing worker-1.
        local ok=T;
        for ( own in expected_owners ) if ( [worker,own] !in global_eos_acks ) ok=F;
        if ( ok ) { worker1_released=T; Cluster::publish(Cluster::node_topic("worker-1"),start_source,"worker-1",view$id); }
        }
    manager_maybe_decide();
    }
event prepared(owner: string,incarnation: string,view_id: string,complete: bool,n: count)
    {
    if ( Cluster::local_node_type()!=Cluster::MANAGER || ! installed || view_id!=view$id || owner !in expected_owners || incarnation!=view$nodes[owner] ) return;
    prepare_votes[owner]=complete; prepare_counts[owner]=n; manager_maybe_decide();
    }
event commit_window(view_id: string)
    {
    if ( Cluster::local_node_type()!=Cluster::PROXY || ! installed || view_id!=view$id || bad || ! owner_prepared || owner_committed ) return;
    owner_committed=T;
    facts=sort(facts,compare_facts);
    for ( i in facts )
        {
        local f=facts[i]; local o=f$o;
        source_clock=event_time(o);
        local is_reply=o?$reply;
        local semantic=observation_digest(o);
        if ( [f$key,f$token,is_reply] in fact_identity )
            { if ( fact_identity[f$key,f$token,is_reply]!=semantic ) { mark_bad("conflicting query token content"); break; } next; }
        if ( |fact_identity|>=max_owner_facts ) { mark_bad("bounded reduction token cache overflow"); break; }
        fact_identity[f$key,f$token,is_reply]=semantic;
        if ( ! is_reply )
            {
            local bound=DNScat2::local_dispatch(o);
            token_bindings[f$key,f$token]=bound;
            trace([$action="QUERY_BOUND",$worker=f$worker,$owner=Cluster::node,$token=f$token,$observed=source_clock,$source_query=o$at,$scope=o$scope,$sid=f$key$sid,$generation=bound$generation,$complete=bound$valid]);
            }
        else
            {
            if ( [f$key,f$token] !in token_bindings || ! token_bindings[f$key,f$token]$valid )
                { trace([$action="UNKNOWN_QUERY",$worker=f$worker,$owner=Cluster::node,$token=f$token,$observed=source_clock]); next; }
            o$request=token_bindings[f$key,f$token];
            DNScat2::local_dispatch(o);
            trace([$action="PAIR_REDUCED",$worker=f$worker,$owner=Cluster::node,$token=f$token,$observed=source_clock,$source_query=o$at,$scope=o$scope,$sid=f$key$sid,$generation=o$request$generation]);
            }
        }
    trace([$action="OWNER_DONE",$owner=Cluster::node,$facts=|facts|,$complete=!bad,$observed=source_clock,$has_observation=|facts|>0]);
    Cluster::publish(Cluster::manager_topic,owner_done,Cluster::node,Cluster::node_id(),view$id,|facts|);
    }
event owner_done(owner: string,incarnation: string,view_id: string,n: count)
    {
    if ( Cluster::local_node_type()!=Cluster::MANAGER || ! installed || view_id!=view$id || owner !in expected_owners || incarnation!=view$nodes[owner] ) return;
    add done_owners[owner];
    if ( |done_owners|==|expected_owners| && ! shutdown_scheduled ) { shutdown_scheduled=T; schedule 1sec { finish() }; }
    }
event failure(node: string,view_id: string,reason: string)
    {
    if ( Cluster::local_node_type()!=Cluster::MANAGER || ! installed || view_id!=view$id ) return;
    bad=T; trace([$action="WINDOW_FAILURE",$detail=reason]);
    # Operational failure never authorizes reduction. Give diagnostics/ACKs a
    # bounded drain interval, then shut down this one finite window.
    if ( ! shutdown_scheduled ) { shutdown_scheduled=T; schedule 1sec { finish() }; }
    }
event zeek_init() &priority=-10
    {
    # Only the one approved security output is forwarded to the manager. No
    # DNS/connection payload log stream is sent from workers or proxies.
    if ( finite_mode && Cluster::local_node_type()==Cluster::PROXY )
        {
        local notice_filter=Log::get_filter(Notice::LOG,"default");
        notice_filter$log_remote=T;
        Log::remove_filter(Notice::LOG,"default");
        Log::add_filter(Notice::LOG,notice_filter);
        }
    }
event zeek_init() &priority=-20
    {
    if ( ! finite_mode ) { trace([$action="LIVE_CLUSTER_DISABLED",$detail="explicit finite input mode required; live idle/watermark qualification open"]); terminate(); return; }
    if ( Cluster::local_node_type()==Cluster::WORKER && ! reading_traces() ) { trace([$action="LIVE_CLUSTER_DISABLED",$detail="finite workers require assigned immutable -r PCAP input"]); terminate(); return; }
    trace([$action="INIT",$detail=fmt("%s/%s/%s",zeek_version(),Cluster::backend,Cluster::local_node_type())]);
    }
event finish()
    {
    finished=T;
    if ( Cluster::local_node_type()==Cluster::MANAGER ) { Cluster::publish(Cluster::worker_topic,finish); Cluster::publish(Cluster::proxy_topic,finish); }
    trace([$action="FINISH",$complete=!bad]);
    terminate();
    }

event zeek_done()
    {
    print fmt("{\"action\":\"CLUSTER_STATS\",\"node\":\"%s\",\"source_facts\":%d,\"source_dropped\":%d,\"owner_facts\":%d,\"transport_entries\":%d,\"token_bindings\":%d,\"semantic_entries\":%d,\"fact_acks\":%d,\"eos_sources\":%d,\"limit_worker_facts\":%d,\"limit_owner_facts\":%d,\"limit_tokens\":%d}",Cluster::node,|source_buffer|,source_dropped,|facts|,|transport_hash|,|token_bindings|,|fact_identity|,|global_fact_acks|,|eos_seen|,max_worker_facts,max_owner_facts,max_tokens);
    }
