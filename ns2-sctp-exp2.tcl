# EXAMPLE SCRIPT 1
#
# Simply drops one packet and later fast rtx it.

# this needs to be set for tracing SCTP packets
Trace set show_sctphdr_ 1

set ns [new Simulator]
set nf [open sctp.nam w]
$ns namtrace-all $nf

set allchan [open all.tr w]
$ns trace-all $allchan

proc finish {} {
    global ns nf allchan sctp0 sctp1

    set PERL "/usr/bin/perl"
    set USERHOME [exec env | grep "^HOME" | sed /^HOME=/s/^HOME=//]
    #set NSHOME "$USERHOME/proj/ns-allinone-2.1b8.sctp"
    #set SETFID "$NSHOME/ns-2.1b8/bin/set_flow_id"
    #set RAW2XG_SCTP "$NSHOME/ns-2.1b8/bin/raw2xg-sctp"
    set NSHOME "/home/ns-allinone-2.29"
    set XGRAPH "$NSHOME/bin/xgraph"
    set SETFID "$NSHOME/ns-2.29/bin/set_flow_id"
    set RAW2XG_SCTP "$NSHOME/ns-2.29/bin/raw2xg-sctp"

    #puts "Congestion Window at Sender [$sctp0 set cwnd_]    Total Bytes Received [$sctp1 set bytes_recvd_]"
    puts "Congestion Window at Sender [$sctp0 set cwnd_]"
    $ns flush-trace
    close $nf
    close $allchan

    exec $PERL $SETFID -s all.tr | \
        $PERL $RAW2XG_SCTP -A -q > temp.rands
    #exec $XGRAPH -bb -tk -nl -m -x time -y packets temp.rands &

    #exec nam sctp.nam &

    exit 0
}

set false      0
set true      1

set n0 [$ns node]
set n1 [$ns node]
$ns duplex-link $n0 $n1 .5Mb 200ms DropTail
$ns duplex-link-op $n0 $n1 orient right
#$ns queue-limit $n0 $n1 93000

set err [new ErrorModel/List]
$err droplist {15}
$ns lossmodel $err $n0 $n1

# NOTE: The debug files (in this example, they would be debug.SctpAgent.0
#      and debug.SctpAgent.1) contain a lot of useful info. They can be
#      used to trace every packet sent/rcvd/processed.
#
#set sctp0 [new Agent/SCTP/Tezpur]
set sctp0 [new Agent/SCTP/Timestamp]
$ns attach-agent $n0 $sctp0
$sctp0 set fid_ 0
$sctp0 set debugMask_ 0x00303000  # u can use -1 to turn on everything
$sctp0 set debugFileIndex_ 0
$sctp0 set mtu_ 1500
#$sctp0 set dataChunkSize_ 1468
$sctp0 set numOutStreams_ 1
$sctp0 set initialCwndMultiplier_ 2
$sctp0 set useMaxBurst_ $true
$sctp0 set dataChunkSize_ 1456        ;#By Manoj
#$sctp0 set tz_debug_ 1
#$sctp0 set tz_WinIncrOpt_ 9


set trace_ch [open trace.sctp w]
$sctp0 set trace_all_ 0 # do not trace all variables on one line
$sctp0 trace cwnd_
$sctp0 attach $trace_ch

#set sctp1 [new Agent/SCTP/Tezpur]
set sctp1 [new Agent/SCTP/Timestamp]
$ns attach-agent $n1 $sctp1
$sctp1 set debugMask_ -1
$sctp1 set debugFileIndex_ 1
$sctp1 set dataChunkSize_ 1456        ;#By Manoj
$sctp1 set mtu_ 1500
$sctp1 set initialRwnd_ 131072
$sctp1 set useDelayedSacks_ $true

$ns color 0 Red
$ns color 1 Blue

$ns connect $sctp0 $sctp1

set ftp0 [new Application/FTP]
$ftp0 attach-agent $sctp0

$ns at 0.5 "$ftp0 start"
$ns at 5.0 "finish"

$ns run
