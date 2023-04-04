/*NS2 main file for SCTP-Tezpur, an experimental SCTP layer which modifies
* the congestion control algorithm in the original specification .
* It monitors the rtt and accordingly changes the congestion window cwnd
* as long as the rtt changes, i.e. if crtt<=prtt, cwnd is increased else it is
* decreased, where crtt is the current rtt and prtt is the prev.
* IT IS PRIMARILY BASED THE RATIO CONSISTING OF CURRENT RTT AND THRESHOLD RTT
* Author: Manoj Dahal, 03/08/2005, Tezpur University*/

/*
* CURRENTLY, THE FOLLOWING TECHNIQUES ARE NOT IMPLEMENTED IN SCTP-TEZPUR.
*
  Latest TECHNIQUES includes (All router assisted)
    i) Queuing Delay(QD) Based
  ii) Active Connections and Empty Buffers(ACEB) Technique
& iii) Threshold Queue Lenght(TQL) based (Suggested BY DKS)
 
  04/12/2003
 
    July 2005:
        Threshold RTT have been tried to fix it dynamically.
*/

/*#ifndef lint
static const char rcsid[]=
    "@(#) $Header: /home/manoj/research/ns-allinone-2.27/ns-2.27/sctp/sctp-tezpur.cc,v 1.0 2001/12/20 15:43:02 mdahal Exp $ (TU)";
#endif*/

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) < (b)) ? (b) : (a))
#define    MIN(x,y)    (((x)<(y))?(x):(y))
#define    MAX(x,y)    (((x)>(y))?(x):(y))

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <sys/types.h>

#include "ip.h"
#include "flags.h"
#include "packet.h"
#include "random.h"
#include "sctp-tezpur.h"
#include "sctpDebug.h"

/* TCP Tezpur */

static class TezpurSctpClass : public TclClass {
public:
    TezpurSctpClass() : TclClass("Agent/SCTP/Tezpur") {}
    TclObject* create(int argc, const char*const* argv) {
        return (new TezpurSctpAgent());
    }

} classSctpTezpur;

TezpurSctpAgent::TezpurSctpAgent() :TimestampSctpAgent(), tz_debug_(0),tz_WinIncrOpt_(9), tz_ftrace_(0),tz_rtt_thin_(11), \
tz_edge_(0), tz_delay_(0),uiUseCmt(0)
//, tz_tr_decclamp_(-9),tz_tr_incclamp_(-6),tz_tr_incclamp_onzero_(0)  /*26/06/2005;07.00pm*/
// drate_cal_timer_(this,&TezpurSctpAgent::DataRateCal_Timeout),Tdc_(0.025), \
tz_req_drate_ (0), tz_act_drate_(0), tz_lasttime_(0), tz_ack_counter_(0)
//tz_tr_decclamp_(-6),tz_tr_incclamp_(-3),tz_tr_incclamp_onzero_(0) //26/06/2005;07.00pm
//tz_tr_decclamp_(-3),tz_tr_incclamp_(-1),tz_tr_incclamp_onzero_(0) //22/06/2005;07.42am
//tz_tr_decclamp_(-4),tz_tr_incclamp_(-2),tz_tr_incclamp_onzero_(0) //22/06/2005;07.42am
//tz_tr_decclamp_(-6),tz_tr_incclamp_(-2),tz_tr_incclamp_onzero_(0) //22/06/2005;07.42am
//tz_tr_decclamp_(-2),tz_tr_incclamp_(0),tz_tr_incclamp_onzero_(0) //21/06/2005;08.20pm
//tz_tr_decclamp_(-6),tz_tr_incclamp_(-2),tz_tr_incclamp_onzero_(0);//the defaults for prev version
//tz_tr_decclamp_(-12),tz_tr_incclamp_(10),tz_tr_incclamp_onzero_(0);// After probe is over
    //Previous decclamp_ was '-15'
    //Previous decclamp_ was '-10' & incclamp_ was '10'
    //Previous decclamp_ was '-9' & incclamp_ was '9'
    //Previous decclamp_ was '-8' & incclamp_ was '8'
    //Previous decclamp_ was '-7' & incclamp_ was '7'
{
/*bind_time("tz_crtt_", &tz_crtt_);
bind_time("tz_rtt_thresh_", &tz_rtt_thresh_);
bind_time("tz_rtt_thper_", &tz_rtt_thper_);
bind_time("tz_min_rtt_", &tz_min_rtt_);
bind_time("tz_max_rtt_", &tz_max_rtt_);
bind_time("tz_artt_", &tz_artt_);*/
//bind_time("tz_rtt_thin_", &tz_rtt_thin_);
//bind("tz_rtt_thin_", &tz_rtt_thin_);
bind("tz_debug_",&tz_debug_);
//bind_time("tz_thrtt_const_",&tz_thrtt_const_);
//bind_time("tz_cwndincr_",&tz_cwndincr_);
bind("tz_WinIncrOpt_",&tz_WinIncrOpt_);
bind("tz_edge_",&tz_edge_); //22/08/2005
//bind("tz_cong_loss_cnt_",&tz_cong_loss_cnt_);
//bind("tz_mxrtt_cwnd_",&tz_mxrtt_cwnd_);
//bind_time("tz_max_artt_", &tz_max_artt_);
bind("tz_ftrace_",&tz_ftrace_);
  //bind("bytes_recvd_", &uiBytesRecvd); //By Manoj 05/08/2005

  bind("use_cmt_", &uiUseCmt); //By Manoj 23/08/2005
  //bind("use_cmt_", &uiCMTType); //By Manoj 23/08/2005
//printf("Construct:Test....Sctp-Tezpur\n");
/* 20/04/2005*/
tz_next_sctp_++;
tz_sctp_id_ = tz_next_sctp_;

}

TezpurSctpAgent::~TezpurSctpAgent()
{
//printf("Destruct:Test....Sctp-Tezpur\n");
if (tz_ftrace_)
    fclose(tz_tracefd_);
}

void TezpurSctpAgent::delay_bind_init_all()
{

  delay_bind_init_one("tz_rtt_thin_"); //By Manoj 05/08/2005
  delay_bind_init_one("tz_delay_"); //By Manoj 22/08/2005

  TimestampSctpAgent::delay_bind_init_all();
}

int TezpurSctpAgent::delay_bind_dispatch(const char *cpVarName, const char *cpLocalName, TclObject *opTracer)
{
  if(delay_bind(cpVarName, cpLocalName, "tz_rtt_thin_", &tz_rtt_thin_, opTracer)) //By Manoj 05/08/2005
    return TCL_OK;
  if(delay_bind(cpVarName, cpLocalName, "tz_delay_", &tz_delay_, opTracer)) //By Manoj 22/08/2005
    return TCL_OK;

  return TimestampSctpAgent::delay_bind_dispatch(cpVarName, cpLocalName, opTracer);
}

  void  TezpurSctpAgent::OptionReset()
{
    TimestampSctpAgent::OptionReset();
}
void TezpurSctpAgent::recv(Packet *opInPkt, Handler*)
{
  /* Let's make sure that a Reset() is called, because it isn't always
  * called explicitly with the "reset" command. For example, wireless
  * nodes don't automatically "reset" their agents, but wired nodes do.
  */
  if(eState == SCTP_STATE_UNINITIALIZED)
    Reset();

  DBG_I(recv);

  hdr_ip *spIpHdr = hdr_ip::access(opInPkt);
  hdr_sctp *spSctpHdr = hdr_sctp::access(opInPkt);
  PacketData *opInPacketData = (PacketData *) opInPkt->userdata();
  u_char *ucpInData = opInPacketData->data();
  u_char *ucpCurrInChunk = ucpInData;
  int iRemainingDataLen = opInPacketData->size();

  u_char ucpOutData[uiMaxPayloadSize];
  u_char *ucpCurrOutData = ucpOutData;

  /* local variable which maintains how much data has been filled in the current
  * outgoing packet
  */
  int iOutDataSize = 0;

  memset(ucpOutData, 0, uiMaxPayloadSize);
  memset(spSctpTrace, 0,
    (uiMaxPayloadSize / sizeof(SctpChunkHdr_S)) * sizeof(SctpTrace_S) );

  spReplyDest = GetReplyDestination(spIpHdr);

  eStartOfPacket = TRUE;

  do
    {
      DBG_PL(recv, "iRemainingDataLen=%d"), iRemainingDataLen DBG_PR;

      /* processing chunks may need to generate response chunks, so the
      * current outgoing packet *may* be filled in and our out packet's data
      * size is incremented to reflect the new data
      */
      iOutDataSize += ProcessChunk(ucpCurrInChunk, &ucpCurrOutData);
      NextChunk(&ucpCurrInChunk, &iRemainingDataLen);
    }
  while(ucpCurrInChunk != NULL);

  /* Let's see if we have any response chunks (currently only handshake related)
  * to transmit.
  *
  * Note: We don't bundle these responses (yet!)
  */
  if(iOutDataSize > 0)
    {
      SendPacket(ucpOutData, iOutDataSize, spReplyDest);
      DBG_PL(recv, "responded with control chunk(s)") DBG_PR;
    }

  /* Let's check to see if we need to generate and send a SACK chunk.
  *
  * Note: With uni-directional traffic, SACK and DATA chunks will not be
  * bundled together in one packet.
  * Perhaps we will implement this in the future? 
  */
  if(eSackChunkNeeded == TRUE)
    {
      memset(ucpOutData, 0, uiMaxPayloadSize);
      iOutDataSize = BundleControlChunks(ucpOutData);
      iOutDataSize += GenChunk(SCTP_CHUNK_SACK, ucpOutData+iOutDataSize);
      SendPacket(ucpOutData, iOutDataSize, spReplyDest);
      DBG_PL(recv, "SACK sent (%d bytes)"), iOutDataSize DBG_PR;
      eSackChunkNeeded = FALSE;  // reset AFTER sent (o/w breaks dependencies)
    }

  /* Do we need to transmit a FORWARD TSN chunk??
  */
  if(eForwardTsnNeeded == TRUE)
    {
      memset(ucpOutData, 0, uiMaxPayloadSize);
      iOutDataSize = BundleControlChunks(ucpOutData);
      iOutDataSize += GenChunk(SCTP_CHUNK_FORWARD_TSN, ucpOutData+iOutDataSize);
      SendPacket(ucpOutData, iOutDataSize, spNewTxDest);
      DBG_PL(recv, "FORWARD TSN chunk sent") DBG_PR;
      eForwardTsnNeeded = FALSE; // reset AFTER sent (o/w breaks dependencies)
    }

  /* Do we want to send out new DATA chunks in addition to whatever we may have
  * already transmitted? If so, we can only send new DATA if no marked chunks
  * are pending retransmission.
  *
  * Note: We aren't bundling with what was sent above, but we could. Just
  * avoiding that for now... why? simplicity :-)
  */
  if(eSendNewDataChunks == TRUE && eMarkedChunksPending == FALSE)
    {
    //printf("CMT Type %d Use CMT %d\n !", uiCMTType,uiUseCmt);
        SctpAgent::SendMuch();      // Send new data till our cwnd is full!
      eSendNewDataChunks = FALSE; // reset AFTER sent (o/w breaks dependencies)
    }

  delete hdr_sctp::access(opInPkt)->SctpTrace();
  hdr_sctp::access(opInPkt)->SctpTrace() = NULL;
  Packet::free(opInPkt);
  opInPkt = NULL;
  DBG_X(recv);
}
/*void TezpurSctpAgent::sendmsg(int iNumBytes, const char *cpFlags)
{
    SctpAgent::sendmsg(iNumBytes,cpFlags);
}
  int  TezpurSctpAgent::command(int argc, const char*const* argv)
{
    return SctpAgent::command(argc, argv);
}*/


void TezpurSctpAgent::sendmsg(int iNumBytes, const char *cpFlags)
{
  /* Let's make sure that a Reset() is called, because it isn't always
  * called explicitly with the "reset" command. For example, wireless
  * nodes don't automatically "reset" their agents, but wired nodes do.
  */
  if(eState == SCTP_STATE_UNINITIALIZED)
    Reset();

  DBG_I(sendmsg);

  u_char ucpOutData[uiMaxPayloadSize];
  int iOutDataSize = 0;
  AppData_S *spAppData = (AppData_S *) cpFlags;
  Node_S *spNewNode = NULL;
  int iMsgSize = 0;
  u_int uiMaxFragSize = uiMaxDataSize - sizeof(SctpDataChunkHdr_S);

  if(iNumBytes == -1)
    eDataSource = DATA_SOURCE_INFINITE;    // Send infinite data
  else
    eDataSource = DATA_SOURCE_APPLICATION; // Send data passed from app
     
  if(eDataSource == DATA_SOURCE_APPLICATION)
    {
      if(spAppData != NULL)
    {
      /* This is an SCTP-aware app!! Anything the app passes down
      * overrides what we bound from TCL.
      */
      DBG_PL (sendmsg, "sctp-aware app: iNumBytes=%d"), iNumBytes DBG_PR;
      spNewNode = new Node_S;
      uiNumOutStreams = spAppData->usNumStreams;
      uiNumUnrelStreams = spAppData->usNumUnreliable;
      spNewNode->eType = NODE_TYPE_APP_LAYER_BUFFER;
      spNewNode->vpData = spAppData;
      InsertNode(&sAppLayerBuffer, sAppLayerBuffer.spTail, spNewNode, NULL);
    }
      else
    {
      /* This is NOT an SCTP-aware app!! We rely on TCL-bound variables.
      */
      DBG_PL (sendmsg, "non-sctp-aware app: iNumBytes=%d"),iNumBytes DBG_PR;
      uiNumOutStreams = 1; // non-sctp-aware apps only use 1 stream
      uiNumUnrelStreams = (uiNumUnrelStreams > 0) ? 1 : 0;

      /* To support legacy applications and uses such as "ftp send
      * 12000", we "fragment" the message. _HOWEVER_, this is not
      * REAL SCTP fragmentation!! We do not maintain the same SSN or
      * use the B/E bits. Think of this block of code as a shim which
      * breaks up the message into useable pieces for SCTP.
      */
      for(iMsgSize = iNumBytes;
          iMsgSize > 0;
          iMsgSize -= MIN(iMsgSize, uiMaxFragSize) )
        {
          spNewNode = new Node_S;
          spNewNode->eType = NODE_TYPE_APP_LAYER_BUFFER;
          spAppData = new AppData_S;
          spAppData->usNumStreams = uiNumOutStreams;
          spAppData->usNumUnreliable = uiNumUnrelStreams;
          spAppData->usStreamId = 0; 
          spAppData->usReliability = uiReliability;
          spAppData->eUnordered = eUnordered;
          spAppData->uiNumBytes = MIN(iMsgSize, uiMaxFragSize);
          spNewNode->vpData = spAppData;
          InsertNode(&sAppLayerBuffer, sAppLayerBuffer.spTail,
            spNewNode, NULL);
        }
    }     

      if(uiNumOutStreams > MAX_NUM_STREAMS)
    {
      fprintf(stderr, "%s number of streams (%d) > max (%d)\n",
          "SCTP ERROR:",
          uiNumOutStreams, MAX_NUM_STREAMS);
      DBG_PL(sendmsg, "ERROR: number of streams (%d) > max (%d)"),
        uiNumOutStreams, MAX_NUM_STREAMS DBG_PR;
      DBG_PL(sendmsg, "exiting...") DBG_PR;
      exit(-1);
    }
      else if(uiNumUnrelStreams > uiNumOutStreams)
    {
      fprintf(stderr, "%s number of unreliable streams (%d) > total (%d)\n",
          "SCTP ERROR:",
          uiNumUnrelStreams, uiNumOutStreams);
      DBG_PL(sendmsg,
        "ERROR: number of unreliable streams (%d) > total (%d)"),
        uiNumUnrelStreams, uiNumOutStreams DBG_PR;
      DBG_PL(sendmsg, "exiting...") DBG_PR;
      exit(-1);
    }

      if(spAppData->uiNumBytes + sizeof(SctpDataChunkHdr_S)
    > MAX_DATA_CHUNK_SIZE)
    {
      fprintf(stderr, "SCTP ERROR: message size (%d) too big\n",
          spAppData->uiNumBytes);
      fprintf(stderr, "%s data chunk size (%d) > max (%d)\n",
          "SCTP ERROR:",
          spAppData->uiNumBytes + sizeof(SctpDataChunkHdr_S),
          MAX_DATA_CHUNK_SIZE);
      DBG_PL(sendmsg, "ERROR: message size (%d) too big"),
        spAppData->uiNumBytes DBG_PR;
      DBG_PL(sendmsg, "ERROR: data chunk size (%d) > max (%d)"),
        spAppData->uiNumBytes + sizeof(SctpDataChunkHdr_S),
        MAX_DATA_CHUNK_SIZE
        DBG_PR;
      DBG_PL(sendmsg, "exiting...") DBG_PR;
      exit(-1);
    }
      else if(spAppData->uiNumBytes + sizeof(SctpDataChunkHdr_S)
          > uiMaxDataSize)
    {
      fprintf(stderr, "SCTP ERROR: message size (%d) too big\n",
          spAppData->uiNumBytes);
      fprintf(stderr,
          "%s data chunk size (%d) + SCTP/IP header(%d) > MTU (%d)\n",
          "SCTP ERROR:",
          spAppData->uiNumBytes + sizeof(SctpDataChunkHdr_S),
          SCTP_HDR_SIZE + uiIpHeaderSize, uiMtu);
      fprintf(stderr, "          %s\n",
          "...chunk fragmentation is not yet supported!");
      DBG_PL(sendmsg, "ERROR: message size (%d) too big"),
        spAppData->uiNumBytes DBG_PR;
      DBG_PL(sendmsg, "exiting...") DBG_PR;
      exit(-1);
    }
    }

  switch(eState)
    {
    case SCTP_STATE_CLOSED:
      DBG_PL(sendmsg, "sending INIT") DBG_PR;

      /* This must be done especially since some of the legacy apps use their
      * own packet type (don't ask me why). We need our packet type to be
      * sctp so that our tracing output comes out correctly for scripts, etc
      */
      set_pkttype(PT_SCTP);
      iOutDataSize = GenChunk(SCTP_CHUNK_INIT, ucpOutData);
      opT1InitTimer->resched(spPrimaryDest->dRto);
      eState = SCTP_STATE_COOKIE_WAIT;
      SendPacket(ucpOutData, iOutDataSize, spPrimaryDest);
      break;
     
    case SCTP_STATE_ESTABLISHED:
      if(eDataSource == DATA_SOURCE_APPLICATION)
    {
      SctpAgent::SendMuch();     
    }
      else if(eDataSource == DATA_SOURCE_INFINITE)
    {
      fprintf(stderr, "[sendmsg] ERROR: unexpected state... %s\n",
          "sendmsg called more than once for infinite data");
      DBG_PL(sendmsg,
        "ERROR: unexpected state... %s"),
        "sendmsg called more than once for infinite data" DBG_PR;
      DBG_PL(sendmsg, "exiting...") DBG_PR;
      exit(-1);
    }
      break;
     
    default: 
      /* If we are here, we assume the application is trying to send data
      * before the 4-way handshake has completed. ...so buffering the
      * data is ok, but DON'T send it yet!! 
      */
      break;
    }

  DBG_X(sendmsg);
}

int TezpurSctpAgent::command(int argc, const char*const* argv)
{
  DBG_I(command); // internal check is done to avoid printing if file is unopen!

  double dCurrTime = Scheduler::instance().clock();
  DBG_PL(command, "<time:%f> argc=%d argv[1]=%s"),
    dCurrTime, argc, argv[1] DBG_PR;

  Tcl& oTcl = Tcl::instance();
  Node *opNode = NULL;
  int iNsAddr;
  int iNsPort;
  NsObject *opTarget = NULL;
  NsObject *opLink = NULL;
  int iRetVal;

  if(argc == 2) 
    {
      if (strcmp(argv[1], "reset") == 0)
    {
      Reset();
      DBG_X(command);
      return (TCL_OK);
    }
      else if (strcmp(argv[1], "close") == 0)
    {
      Close();
      DBG_X(command);
      return (TCL_OK);
    }
    }
  else if(argc == 3)
    {
      if (strcmp(argv[1], "advance") == 0)
    {
      DBG_X(command);
      return (TCL_OK);
    }
      else if (strcmp(argv[1], "set-multihome-core") == 0)
    {
      opCoreTarget = (Classifier *) TclObject::lookup(argv[2]);
      if(opCoreTarget == NULL)
        {
          oTcl.resultf("no such object %s", argv[4]);
          return (TCL_ERROR);
        }
      DBG_X(command);
      return (TCL_OK);
    }
      else if (strcmp(argv[1], "set-primary-destination") == 0)
    {
      opNode = (Node *) TclObject::lookup(argv[2]);
      if(opNode == NULL)
        {
          oTcl.resultf("no such object %s", argv[2]);
          return (TCL_ERROR);
        }
      iRetVal = SetPrimary( opNode->address() );

      if(iRetVal == TCL_ERROR)
        {
          fprintf(stderr, "[SctpAgent::command] ERROR:"
              "%s is not a valid destination\n", argv[2]);
          DBG_X(command);
          return (TCL_ERROR);
        }
      DBG_X(command);
      return (TCL_OK);
    }
      else if (strcmp(argv[1], "force-source") == 0)
    {
      opNode = (Node *) TclObject::lookup(argv[2]);
      if(opNode == NULL)
        {
          oTcl.resultf("no such object %s", argv[2]);
          return (TCL_ERROR);
        }
      iRetVal = ForceSource( opNode->address() );

      if(iRetVal == TCL_ERROR)
        {
          fprintf(stderr, "[SctpAgent::command] ERROR:"
              "%s is not a valid source\n", argv[2]);
          DBG_X(command);
          return (TCL_ERROR);
        }
      DBG_X(command);
      return (TCL_OK);
    }
      else if (strcmp(argv[1], "print") == 0)
    {
      if(eTraceAll == TRUE)
        TraceAll();
      else
        TraceVar(argv[2]);
      DBG_X(command);
      return (TCL_OK);
    }
    }
  else if(argc == 4)
    {
      if (strcmp(argv[1], "add-multihome-destination") == 0)
    {
      iNsAddr = atoi(argv[2]);
      iNsPort = atoi(argv[3]);
      AddDestination(iNsAddr, iNsPort);
      DBG_X(command);
      return (TCL_OK);
    }
    }
  else if(argc == 6)
    {
      if (strcmp(argv[1], "add-multihome-interface") == 0)
    {
      iNsAddr = atoi(argv[2]);
      iNsPort = atoi(argv[3]);
      opTarget = (NsObject *) TclObject::lookup(argv[4]);
      if(opTarget == NULL)
        {
          oTcl.resultf("no such object %s", argv[4]);
          return (TCL_ERROR);
        }
      opLink = (NsObject *) TclObject::lookup(argv[5]);
      if(opLink == NULL)
        {
          oTcl.resultf("no such object %s", argv[5]);
          return (TCL_ERROR);
        }
      AddInterface(iNsAddr, iNsPort, opTarget, opLink);
      DBG_X(command);
      return (TCL_OK);
    }
    }

  DBG_X(command);
  return (Agent::command(argc, argv));
}

void TezpurSctpAgent::Reset()
{
  TimestampSctpAgent::Reset();

  Node_S *spCurrNode = NULL;
  SctpDest_S *spCurrDest = NULL;

  for(spCurrNode = sDestList.spHead; spCurrNode != NULL; spCurrNode = spCurrNode->spNext)
    {
      spCurrDest = (SctpDest_S *) spCurrNode->vpData;

    spCurrDest->tzCB.tz_crtt_ = 0 ;
    spCurrDest->tzCB.tz_prtt_ = 0 ;
    spCurrDest->tzCB.tz_pprtt_ = 0 ;
    spCurrDest->tzCB.tz_min_rtt_ = 0 ;
    spCurrDest->tzCB.tz_max_rtt_ = 0 ;
    spCurrDest->tzCB.tz_rtt_cnt_ = 0 ;
    spCurrDest->tzCB.tz_mxrtt_cnt_ = 0 ;
    spCurrDest->tzCB.tz_prtt_seq_ = 0 ;
    spCurrDest->tzCB.tz_avg_tot_ = 0 ;
    spCurrDest->tzCB.tz_rtt_thresh_ = 0 ; // RTT Threshold
    spCurrDest->tzCB.tz_cwnd_max_ = 1 ;
    //spCurrDest->tzCB.tz_sldown_ = 0 ;
    spCurrDest->tzCB.tz_rtt_thper_ = 50 ;
    //spCurrDest->tzCB.tz_rtt_thin_ = 1.1 ; //2 ;
    spCurrDest->tzCB.tz_count_ = 0 ;
    spCurrDest->tzCB.tz_rtt_tot_ = 0 ;
    spCurrDest->tzCB.tz_artt_ = 0 ;
    spCurrDest->tzCB.tz_slow_cnt_ = 0 ;
    spCurrDest->tzCB.tz_rtt_thresh_ = 0 ;
    spCurrDest->tzCB.tz_edge_ = 0 ;
    spCurrDest->tzCB.tz_base_rtt_ = 0 ;
    spCurrDest->tzCB.tz_thrtt_const_ = 1 ;
    spCurrDest->tzCB.tz_cwndincr_ = 0 ;
    spCurrDest->tzCB.tz_cong_flag_ = 1 ;
    spCurrDest->tzCB.tz_max_cwndincr_ = 2;//1.5 ;
    //spCurrDest->tzCB.tz_cong_loss_cnt_ = 0 ;
    spCurrDest->tzCB.tz_max_artt_ = 0 ;
    spCurrDest->tzCB.tz_min_artt_ = 0 ;
    //spCurrDest->tzCB.tz_mxrtt_cwnd_ = 0 ;
    spCurrDest->tzCB.rtt_thresh_prob_ = 1 ;
    spCurrDest->tzCB.last_rtt_thresh_prob_ = 0 ;
    spCurrDest->tzCB.orgin_rtt_thresh_ = 0 ;
    spCurrDest->tzCB.th_rtt_incr_cnt_ = 0 ;
    spCurrDest->tzCB.th_rtt_decr_cnt_ = 0 ;
    spCurrDest->tzCB.tz_tr_decclamp_ = -9 ;
    spCurrDest->tzCB.tz_tr_incclamp_ = -6 ;
    spCurrDest->tzCB.tz_tr_incclamp_onzero_ = 0 ;
    }
    //tz_rtt_thin_ =  11;//6.5;// 1.1 ; //2 ;//05/08/2005
    //tz_rtt_thin_ = 0 ; //2 ;//05/08/2005
uiCMTType = uiUseCmt;
  /* 05/08/2005 */
if (tz_ftrace_)
{   
char tfl[100];
char tl[20];

strcpy(tfl,"/home/manoj/2005/aug/rtt_trace");
sprintf(tl,"%d",tz_sctp_id_);
strcat(tl,".txt");
strcat(tfl,tl);
printf("File Name = %s\n",tfl);
tz_tracefd_ = fopen(tfl,"w");
fprintf(tz_tracefd_,"Time    RTT    Th RTT    Avg RTT    Cwnd    RTO    Dest\n");
}
}

void TezpurSctpAgent::TzUpdateRTTs(SctpDest_S *spDest)
{
    spDest->tzCB.tz_pprtt_ = spDest->tzCB.tz_prtt_;
    spDest->tzCB.tz_prtt_ = spDest->tzCB.tz_crtt_;
    spDest->tzCB.tz_crtt_ = spDest->dSrtt; //As RTT already updated by 'RttUpdate()'
       
        if (spDest->tzCB.tz_crtt_ < spDest->tzCB.tz_min_rtt_ || spDest->tzCB.tz_min_rtt_ == 0)
              spDest->tzCB.tz_min_rtt_ = spDest->tzCB.tz_crtt_;
        if (spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_max_rtt_ ){
                spDest->tzCB.tz_max_rtt_ = spDest->tzCB.tz_crtt_;
        //spDest->tzCB.tz_mxrtt_cwnd_ =spDest->iCwnd;
    }
    /* 16/05/2004 */
    //if (spDest->tzCB.tz_cwndincr_>0 && spDest->tzCB.tz_crtt_>spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0)
   
    /*
    spDest->tzCB.tz_rtt_var_ = spDest->tzCB.tz_crtt_ - spDest->tzCB.tz_prtt_;
    int k=5;
    if (spDest->tzCB.tz_crtt_>spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0)
    {   
        spDest->tzCB.tz_rtt_incr_pers_[(spDest->tzCB.tz_rtt_incr_per_cnt_ % k)]= (spDest->tzCB.tz_crtt_ - spDest->tzCB.tz_prtt_)/spDest->tzCB.tz_prtt_;
        spDest->tzCB.tz_rtt_incr_per_tot_ = spDest->tzCB.tz_rtt_incr_per_tot_+(spDest->tzCB.tz_crtt_-spDest->tzCB.tz_prtt_)/spDest->tzCB.tz_prtt_;
        spDest->tzCB.tz_rtt_incr_per_cnt_ = spDest->tzCB.tz_rtt_incr_per_cnt_ + 1;
        if (spDest->tzCB.tz_rtt_incr_per_cnt_>k) {
            double tmp=0;
            for (int j=0;j<k;j++)
                tmp=tmp+spDest->tzCB.tz_rtt_incr_pers_[j];
            spDest->tzCB.tz_rtt_incr_per_ = tmp/k;
        }
        else   
        spDest->tzCB.tz_rtt_incr_per_ = spDest->tzCB.tz_rtt_incr_per_tot_/spDest->tzCB.tz_rtt_incr_per_cnt_;
            //spDest->tzCB.tz_rtt_incr_per_ = (spDest->tzCB.tz_crtt_-spDest->tzCB.tz_prtt_);// /spDest->tzCB.tz_prtt_;
    }
    else
        //if (spDest->tzCB.tz_cwndincr_<0 && spDest->tzCB.tz_crtt_<spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0)
        if (spDest->tzCB.tz_crtt_<spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0)
    {
        spDest->tzCB.tz_rtt_decr_pers_[spDest->tzCB.tz_rtt_decr_per_cnt_ % k]= (spDest->tzCB.tz_prtt_ - spDest->tzCB.tz_crtt_)/spDest->tzCB.tz_prtt_;
        spDest->tzCB.tz_rtt_decr_per_tot_ = spDest->tzCB.tz_rtt_decr_per_tot_+(spDest->tzCB.tz_prtt_-spDest->tzCB.tz_crtt_)/spDest->tzCB.tz_prtt_;
        spDest->tzCB.tz_rtt_decr_per_cnt_ = spDest->tzCB.tz_rtt_decr_per_cnt_ + 1;
        if (spDest->tzCB.tz_rtt_decr_per_cnt_>k) {
            double tmp=0;
            for (int j=0;j<k;j++)
                tmp=tmp+spDest->tzCB.tz_rtt_decr_pers_[j];
            spDest->tzCB.tz_rtt_decr_per_ = tmp/k;
        }
        else   
        spDest->tzCB.tz_rtt_decr_per_ = spDest->tzCB.tz_rtt_decr_per_tot_/spDest->tzCB.tz_rtt_decr_per_cnt_;
            //spDest->tzCB.tz_rtt_decr_per_ = (spDest->tzCB.tz_prtt_-spDest->tzCB.tz_crtt_); // /spDest->tzCB.tz_prtt_;

    }
      //if ((spDest->tzCB.tz_crtt_-spDest->tzCB.tz_prtt_)>=(spDest->tzCB.tz_prtt_/2) && spDest->tzCB.tz_prtt_>0) // && spDest->tzCB.tz_crtt_>spDest->tzCB.tz_rtt_thresh_) 12/06/2004 i.
      //if ((spDest->tzCB.tz_crtt_-spDest->tzCB.tz_prtt_)>=(spDest->tzCB.tz_prtt_*3/5) && spDest->tzCB.tz_prtt_>0) // && spDest->tzCB.tz_crtt_>spDest->tzCB.tz_rtt_thresh_) 12/06/2004 ii.
      if ((spDest->tzCB.tz_prtt_-spDest->tzCB.tz_pprtt_)>=(spDest->tzCB.tz_pprtt_/2) && spDest->tzCB.tz_pprtt_>0 && (spDest->tzCB.tz_prtt_-spDest->tzCB.tz_crtt_)>=(spDest->tzCB.tz_prtt_/2)) // && spDest->tzCB.tz_crtt_>spDest->tzCB.tz_rtt_thresh_) 12/06/2004 ii.
          // && spDest->tzCB.tz_crtt_>spDest->tzCB.tz_rtt_thresh_) 12/06/2004 ii.
      spDest->tzCB.tz_rtt_abrupt_ =1;    //27/05/2003 & 12/06/2004
      //spDest->tzCB.tz_rtt_abrupt_ is a flag for abrupt rtt changes
      // As suggested by DKS
      else
          spDest->tzCB.tz_rtt_abrupt_ = 0;
          // Commented on 3/6/2004; Un-commented on 12/06/2004
      */

    int k=30;//No. of RTTs to get recent most Average RTT
   
        spDest->tzCB.tz_rtts_[(spDest->tzCB.tz_count_ % k)]=spDest->tzCB.tz_crtt_;//21/05/2004
    spDest->tzCB.tz_count_ +=1;
        spDest->tzCB.tz_rtt_tot_ +=spDest->tzCB.tz_crtt_;
    if (spDest->tzCB.tz_count_>k){ //21/05/2004
        double rttmp =0;
        for (int j=0;j<k;j++)
            rttmp = rttmp + spDest->tzCB.tz_rtts_[j];
        spDest->tzCB.tz_artt_ = rttmp/k;
    }
    else
          spDest->tzCB.tz_artt_ = spDest->tzCB.tz_rtt_tot_/spDest->tzCB.tz_count_;

        if (spDest->tzCB.tz_base_rtt_==0)
              spDest->tzCB.tz_base_rtt_=tz_edge_*2*(tz_delay_/1000.0+0.000320); //1/10000000);
              //spDest->tzCB.tz_base_rtt_=spDest->tzCB.tz_edge_*2*(spDest->tzCB.tz_delay_/1000.0+0.000320); //1/10000000);
           
        // As We get delay from routers
       
/*
        if (spDest->tzCB.tz_crtt_>0)
            spDest->tzCB.tz_qdelay_=spDest->tzCB.tz_crtt_-spDest->tzCB.tz_base_rtt_;

        if (spDest->tzCB.tz_qdelay_>spDest->tzCB.tz_max_qdelay_ && spDest->tzCB.tz_rtt_thresh_>0)
        spDest->tzCB.tz_max_qdelay_=spDest->tzCB.tz_qdelay_;
*/
        //

        if (spDest->tzCB.tz_rtt_thresh_ == 0)
          {
                //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thin_*spDest->tzCB.tz_crtt_;

              //if (spDest->tzCB.tz_max_qdelay_==0)
              // {
          //if (tz_debug_)
            //printf("WinIncrOpt = %d;    RTT_THIN = %d\n",tz_WinIncrOpt_,tz_rtt_thin_);
                spDest->tzCB.mflag=0;
        /* CHECK THIS */
                //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thin_*spDest->tzCB.tz_min_rtt_;//09/03/2005
                //spDest->tzCB.tz_rtt_thresh_ = tz_rtt_thin_*spDest->tzCB.tz_min_rtt_;//05/08/2005
                //spDest->tzCB.tz_rtt_thresh_ = ((double)tz_rtt_thin_/10.0)*spDest->tzCB.tz_min_rtt_;//17/08/2005
                spDest->tzCB.tz_rtt_thresh_ = ((double)tz_rtt_thin_/10.0)*spDest->tzCB.tz_base_rtt_; //22/08/2005
              /* }
              else
                {
                  spDest->tzCB.mflag=1;
                  spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_base_rtt_+spDest->tzCB.tz_thrtt_const_*spDest->tzCB.tz_max_qdelay_;
                }*/

//printf("Tz_Edge=%d      Base_RTT=%f    RTT_Thresh=%f    \n",spDest->tzCB.tz_edge_,spDest->tzCB.tz_base_rtt_,spDest->tzCB.tz_rtt_thresh_);
printf("Tz_Edge=%d  Base RTT= %f Min_RTT=%f  RTT_Thresh=%f    \n",tz_edge_,spDest->tzCB.tz_base_rtt_,spDest->tzCB.tz_min_rtt_,spDest->tzCB.tz_rtt_thresh_);
//printf("Tz_Edge=%d      Base_RTT=%f    RTT_Thresh=%f    MaxQDel=%f T_RTXCUR=%f\n",spDest->tzCB.tz_edge_,spDest->tzCB.tz_base_rtt_,spDest->tzCB.tz_rtt_thresh_,spDest->tzCB.tz_max_qdelay_,t_rtxcur_);
          }
        /*else
          if (spDest->tzCB.mflag==1)
              spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_base_rtt_+spDest->tzCB.tz_thrtt_const_*spDest->tzCB.tz_max_qdelay_;*/

    if (spDest->tzCB.tz_rtt_thresh_==0 || spDest->tzCB.mflag==2)
            {
          spDest->tzCB.mflag=2;
              spDest->tzCB.tz_rtt_thresh_=spDest->tzCB.tz_thrtt_const_*spDest->tzCB.tz_artt_;
            }

          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thin_*spDest->tzCB.tz_artt_;

        //if (spDest->tzCB.tz_rtt_thresh_<spDest->tzCB.tz_max_rtt_)
          //  spDest->tzCB.tz_rtt_thresh_=spDest->tzCB.tz_rtt_thper_*spDest->tzCB.tz_max_rtt_/100;
        //commented on 09/03/2005
    /*if (spDest->tzCB.tz_prtt_ < spDest->tzCB.tz_min_rtt_ || spDest->tzCB.tz_min_rtt_ == 0)
              spDest->tzCB.tz_min_rtt_ = spDest->tzCB.tz_prtt_;
        //if (spDest->tzCB.tz_prtt_ > spDest->tzCB.tz_max_rtt_ )
          //      spDest->tzCB.tz_max_rtt_ = spDest->tzCB.tz_prtt_;
        if (spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_max_rtt_ ){
                spDest->tzCB.tz_max_rtt_ = spDest->tzCB.tz_crtt_;
        spDest->tzCB.tz_mxrtt_cwnd_ =spDest->iCwnd;
    }*/

        //spDest->tzCB.tz_rtt_thresh_ = (2)*spDest->tzCB.tz_min_rtt_;

    /*Made changes on 17/06/2005 */
        if (spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_!=0)
          spDest->tzCB.tz_rtt_cnt_ -=1;
        /*else  //Commented on 10/07/2005
          if (spDest->tzCB.tz_crtt_ == spDest->tzCB.tz_prtt_ || spDest->tzCB.tz_prtt_==0)
            spDest->tzCB.tz_rtt_cnt_  = 0;*/
    else
      if (spDest->tzCB.tz_crtt_ < spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_!=0)
            spDest->tzCB.tz_rtt_cnt_  +=1;
        /*if (spDest->tzCB.tz_prev_cwnd1_ >=spDest->iCwnd && spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_ )
              spDest->tzCB.tz_rtt_cnt_ -=1;*/ //Commented on 17/06/2005
        //if (spDest->tzCB.tz_rtt_thresh_ > spDest->tzCB.tz_artt_)
      //    spDest->tzCB.tz_artt_ = spDest->tzCB.tz_rtt_thresh_; //21/05/2004   
    if (spDest->tzCB.tz_artt_ > spDest->tzCB.tz_max_artt_)
        spDest->tzCB.tz_max_artt_ = spDest->tzCB.tz_artt_;

    if (spDest->tzCB.tz_min_artt_ == 0 || spDest->tzCB.tz_artt_ < spDest->tzCB.tz_min_artt_) //03/05/2005
        spDest->tzCB.tz_min_artt_ = spDest->tzCB.tz_artt_;

        //double i = spDest->t_rtt_;
    if (tz_debug_>0)
    {
    printf("Tz_Id=%d ;rttthresh= %f; spDest->tzCB.tz_rtt= %f spDest->tzCB.tz_pprtt= %f minrtt= %f  mxrtt= %f RATIO =%f ",tz_debug_,spDest->tzCB.tz_rtt_thresh_,spDest->tzCB.tz_crtt_,spDest->tzCB.tz_pprtt_,spDest->tzCB.tz_min_rtt_,spDest->tzCB.tz_max_rtt_,(spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/spDest->tzCB.tz_crtt_);
    //printf("Tz_Id=%d ;rttthresh= %f; ts echo = %f t_rtt = %f spDest->tzCB.tz_rtt= %f spDest->tzCB.tz_pprtt= %f minrtt= %f  mxrtt= %f RATIO =%f RTXCUR=%f PrevCwnd2=%f PrevCwnd1=%f!",tz_debug_,spDest->tzCB.tz_rtt_thresh_,tcph->ts_echo(),i,spDest->tzCB.tz_crtt_,spDest->tzCB.tz_pprtt_,spDest->tzCB.tz_min_rtt_,spDest->tzCB.tz_max_rtt_,(spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/spDest->tzCB.tz_crtt_,t_rtxcur_,spDest->tzCB.tz_prev_cwnd2_,spDest->tzCB.tz_prev_cwnd1_);
    }
}

//21/03/2005
void TezpurSctpAgent::TzComputeRTTThresh(SctpDest_S *spDest) {


            //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_artt_;
            //return;
    //28/04/2005
    //double tmp_aartt=(spDest->tzCB.tz_max_artt_+spDest->tzCB.tz_min_artt_)/2; //03/05/2005
    //double tmp_aartt=spDest->tzCB.tz_min_artt_; //(spDest->tzCB.tz_max_artt_+spDest->tzCB.tz_min_artt_)/2; //03/05/2005
    /*double tmp_aartt=spDest->tzCB.tz_max_artt_; //(spDest->tzCB.tz_max_artt_+spDest->tzCB.tz_min_artt_)/2; //03/05/2005
    if (rtt_thresh_prob_ == 1)
    {
      if (spDest->tzCB.tz_rtt_thresh_>0)
        {
         
          //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=10) //29/04/2005
          //{
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_ * 1.01; //29/04/05
          //th_rtt_incr_cnt_++; //29/04/2005
            //}
       

        //if (spDest->tzCB.tz_artt_>spDest->tzCB.tz_rtt_thresh_)
        //if (spDest->tzCB.tz_max_artt_>spDest->tzCB.tz_rtt_thresh_) //02/05/2005
        if (tmp_aartt>spDest->tzCB.tz_rtt_thresh_) //03/05/2005
        {   
            //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_artt_;
            //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_max_artt_;
            spDest->tzCB.tz_rtt_thresh_ = tmp_aartt;
            rtt_thresh_prob_ =0;
        }
        else
          //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=10) //29/04/2005
          {
          spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_ * 0.98; //29/04/05
          th_rtt_incr_cnt_++; //29/04/2005
            }
            }     
      }   
      else
        if (rtt_thresh_prob_ == 0)
            //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_artt_;
            //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_max_artt_;
            spDest->tzCB.tz_rtt_thresh_ = tmp_aartt;

    return ;*/
   
    //if (rtt_thresh_prob_ == 1 && spDest->tzCB.tz_rtt_thresh_>0)
    if (spDest->tzCB.rtt_thresh_prob_ >= 1 && spDest->tzCB.tz_rtt_thresh_>0) //19/05/2005;8.35pm
    {
      //if (last_rtt_thresh_prob_ == 0)
      if (spDest->tzCB.orgin_rtt_thresh_ == 0)
      {
          spDest->tzCB.orgin_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_;
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.15,1.5*spDest->tzCB.tz_max_rtt_); //Increase By 5 % subject to maximum of twice max rtt
          //Commented on 14/04/2005
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_ * 1.15; //Increase By 5 % subject to maximum of twice max rtt
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_ * 1.05; //Increase By 5 % subject to maximum of twice max rtt
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.5,2*spDest->tzCB.tz_max_rtt_); //Increase By 5 % subject to maximum of twice max rtt
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.75,2.5*spDest->tzCB.tz_max_rtt_); //Increase By 5 % subject to maximum of twice max rtt
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 2.25,2.5*spDest->tzCB.tz_max_rtt_); //Increase By 5 % subject to maximum of twice max rtt
              //last_rtt_thresh_prob_++;
            if (tz_debug_>0)
          printf("First: Orgin Rtt Thresh %f ; RTT Thresh %f !\n",spDest->tzCB.orgin_rtt_thresh_,spDest->tzCB.tz_rtt_thresh_);
      }
      //else
      //if (last_rtt_thresh_prob_ == 0 || (spDest->tzCB.tz_crtt_ <= spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_ <= spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_pprtt_>0) )
      //if (last_rtt_thresh_prob_ == 0 || (spDest->tzCB.tz_crtt_ <= spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0) )
    /*if (spDest->tzCB.tz_sldown_==1)
          {
        //If there is packet loss; 23/03/2005     
            spDest->tzCB.tz_sldown_=0;
        //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_ * 0.80,orgin_rtt_thresh_); //Decrease By 5 % subject to minimum of Orginal rtt thresh
        spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_,spDest->tzCB.tz_max_rtt_) * 0.80; //14/05/2005
        //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_ * 0.95,orgin_rtt_thresh_); //Decrease By 5 % subject to minimum of Orginal rtt thresh
        rtt_thresh_prob_ = 0; //Again on 14/04/2005
            if (tz_debug_>0)
          printf("Last Slow Down Count %d ; Orgin Rtt Thresh %f ; RTT Thresh %f !\n",spDest->tzCB.tz_sldown_,orgin_rtt_thresh_,spDest->tzCB.tz_rtt_thresh_);
      }
    else*/ //20/05/2005 ;8.20am
      //if (last_rtt_thresh_prob_ == 0 || spDest->tzCB.tz_rtt_cnt_ > -1) //(spDest->tzCB.tz_crtt_ <= spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0) )
      //if (last_rtt_thresh_prob_ == 0 || spDest->tzCB.tz_rtt_cnt_ > 1) //(spDest->tzCB.tz_crtt_ <= spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0) )
      //if (last_rtt_thresh_prob_ == 0 && spDest->tzCB.tz_rtt_cnt_ > 1) //(spDest->tzCB.tz_crtt_ <= spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0) )
      //if (spDest->tzCB.tz_rtt_cnt_ > 1) //(spDest->tzCB.tz_crtt_ <= spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_>0) )
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=10) //14/04/2005
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=30) //14/04/2005
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=50) //14/04/2005
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=60) //15/04/2005
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=50) //12/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=40) //14/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=30) //16/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && th_rtt_incr_cnt_<=40) //16/05/2005 X
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.6)) //17/05/2005 9.20am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.8)) //17/05/2005 9.15pm
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.0)) //17/05/2005 9.30pm
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.5)) //18/05/2005 9.55pm
      //if (spDest->tzCB.tz_rtt_cnt_ > 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.5)) //19/05/2005 8.05pm
      //if (spDest->tzCB.tz_rtt_cnt_ > 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.75)) //19/05/2005 9.15pm
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.75)) //19/05/2005 10.30pm
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*3.0)) //19/05/2005 10.40pm
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.75)) //06/06/2005 9.15am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.5)) //06/06/2005 9.35am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*2.0)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.50)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.30)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.20)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.10)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.05)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.025)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*1.0005)) //07/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*0.9)) //11/06/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*3.0)) //12/06/2005 10.40pm
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.0)) //16/06/2005 8am
      //if (spDest->tzCB.tz_rtt_cnt_ > 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.0)) //16/06/2005 8am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.0)) //16/06/2005 8am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*5.0)) //16/06/2005 8am
      //if (spDest->tzCB.tz_rtt_cnt_ >= 0 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.5)) //16/06/2005 8am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -1 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.5)) //19/06/2005 8.36am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -4 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.5)) //19/06/2005 9.18am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -4 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.0)) //19/06/2005 9.18am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -3 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.0)) //19/06/2005 9.18am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -2 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*3.8)) //21/06/2005 8.30am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -2 && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.2)) //21/06/2005 9.30am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -2  && spDest->tzCB.tz_rtt_thresh_<=(spDest->tzCB.tz_min_rtt_*4.0)) //21/06/2005 9.18am
      //if (spDest->tzCB.tz_rtt_cnt_ >= -2)  //21/06/2005 8.15pm
      if (spDest->tzCB.tz_rtt_cnt_ >= spDest->tzCB.tz_tr_incclamp_) //21/06/2005; 8.18pm
      {
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.05,1.5*spDest->tzCB.tz_max_rtt_); //Increase By 5 % subject to maximum of twice max rtt
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.05,1.1*spDest->tzCB.tz_max_rtt_); //Increase By 5 % subject to maximum of twice max rtt
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.05,3*spDest->tzCB.tz_max_rtt_); //14/04/05
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.02,3*spDest->tzCB.tz_max_rtt_); //14/04/05
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * 1.01,3*spDest->tzCB.tz_max_rtt_); //14/04/05 XX
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.05*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 3pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.10*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.20*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.30*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.35*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.40*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.45*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.55*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.60*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.70*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm X
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.80*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.90*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+1.00*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+1.20*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //16/05/05; 9.40pm
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+1.0*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //18/05/05; 8.50am
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.70*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //18/05/05; 9.00am
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.50*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //18/05/05; 9.15am
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.70*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //18/05/05; 9.30am
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.50*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //18/05/05; 9.35am
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.60*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //18/05/05; 10.05am
          //spDest->tzCB.tz_rtt_thresh_ = min(spDest->tzCB.tz_rtt_thresh_ * (1.0+0.70*spDest->tzCB.tz_min_rtt_),3*spDest->tzCB.tz_max_rtt_); //18/05/05; 9.45pm
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0+0.70*spDest->tzCB.tz_min_rtt_); //19/05/2005; 7.20am New
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0+0.60*spDest->tzCB.tz_min_rtt_); //06/06/2005; 8.40am New
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0+0.50*spDest->tzCB.tz_min_rtt_); //06/06/2005; 8.40am New
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*1.01; //12/06/2005; 8.04am New
          /* 16/06/2005 */
          /*int mflag=0; //18/06/2004; commented on
         
          //if (spDest->tzCB.tz_rtt_cnt_ ==0)
          //{
            spDest->tzCB.tz_tr_incclamp_onzero_++;
            if ((spDest->tzCB.tz_tr_incclamp_onzero_%2)==0)
                mflag=1;
          //}
          //else
        //      mflag=1;
          //if (mflag)*/
          //{
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.01; //13/06/2005; 8.04am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.10; //16/06/2005; 8.04am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.05; //16/06/2005; 8.04am New
          //spDest->tzCB.tz_rtt_thresh_ = (orgin_rtt_thresh_ +spDest->tzCB.tz_artt_)/2; //19/05/2005 7.20am New;commented on 06/06/05
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.01; //17/06/2005; 8.04am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.05; //18/06/2005; 8.04am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.10; //18/06/2005; 7.16pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.05; //18/06/2005; 9.53pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.03; //19/06/2005;10.05am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.02; //19/06/2005;10.50am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.01; //19/06/2005;11.30am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.08; //18/06/2005; 9.53pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.3; //19/06/2005;12.40pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*1.10; //19/06/2005;12.40pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.10/max(rtt_thresh_prob_,1))); //20/06/2005;11.10pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.12/max(rtt_thresh_prob_,1))); //21/06/2005;07.20am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.13/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.14/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.15/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.16/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.17/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.18/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.19/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.20/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.21/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.22/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.25/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.30/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.40/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.50/max(rtt_thresh_prob_,1))); //21/06/2005;07.29am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.11/max(rtt_thresh_prob_,1))); //21/06/2005;08.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.15/max(rtt_thresh_prob_,1))); //21/06/2005;08.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.20/max(rtt_thresh_prob_,1))); //21/06/2005;08.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.15/max(rtt_thresh_prob_,1))); //21/06/2005;08.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.12/max(rtt_thresh_prob_,1))); //21/06/2005;08.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.10/max(rtt_thresh_prob_,1))); //13/07/2005;05.29pm New XX
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.10/max(th_rtt_incr_cnt_,1))); //13/07/2005;05.53pm New
          spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.08/max(spDest->tzCB.th_rtt_incr_cnt_,1))); //13/07/2005;05.53pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(2.50);//+(0.08/max(spDest->tzCB.th_rtt_incr_cnt_,1))); //13/07/2005;05.53pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.09/max(rtt_thresh_prob_,1))); //21/06/2005;08.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.08/max(rtt_thresh_prob_,1))); //23/06/2005;08.46pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.07/max(rtt_thresh_prob_,1))); //23/06/2005;08.46pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.06/max(rtt_thresh_prob_,1))); //23/06/2005;08.46pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.05/max(rtt_thresh_prob_,1))); //23/06/2005;08.46pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.04/max(rtt_thresh_prob_,1))); //23/06/2005;08.46pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.03/max(rtt_thresh_prob_,1))); //23/06/2005;08.46pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.02/max(rtt_thresh_prob_,1))); //23/06/2005;08.46pm New X
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.04/max(rtt_thresh_prob_,1))); //28/06/2005;07.05am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.05/max(rtt_thresh_prob_,1))); //28/06/2005;07.05am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.02/max(rtt_thresh_prob_,1))); //28/06/2005;07.05am New X
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.025/max(rtt_thresh_prob_,1))); //13/07/2005;07.41am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0225/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0215/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.021/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0205/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.02/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0195/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0190/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0185/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New X
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.018/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New X
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0175/max(rtt_thresh_prob_,1))); //13/07/2005;09.31am New X
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.015/max(rtt_thresh_prob_,1))); //11/07/2005;08.35am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.0175/max(rtt_thresh_prob_,1))); //11/07/2005;08.35am New

          /*if (spDest->tzCB.tz_crtt_>spDest->tzCB.tz_rtt_thresh_)
          {
              spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_crtt_;
          rtt_thresh_prob_ = 0; //25/06/2005;8.50pm
          }*/
          spDest->tzCB.rtt_thresh_prob_++ ; //13/07/2005;5.29pm
              spDest->tzCB.last_rtt_thresh_prob_++;
          spDest->tzCB.th_rtt_incr_cnt_++; //14/04/2005
          spDest->tzCB.tz_rtt_cnt_ = 0; //19/05/2005;8pm
          //if (th_rtt_incr_cnt_ >=6)
          //if (th_rtt_incr_cnt_ >=4)
          //if (th_rtt_incr_cnt_ >=5)
          //if (th_rtt_incr_cnt_ >=7)
          //if (th_rtt_incr_cnt_ >=8)
          //if (th_rtt_incr_cnt_ >=3)
          //if (th_rtt_incr_cnt_ >=5)
          //if (th_rtt_incr_cnt_ >=3) X
          //if (th_rtt_incr_cnt_ >=5) //27/06/2005;6am
          //if (th_rtt_incr_cnt_ >=7) //27/06/2005;6am
          //if (th_rtt_incr_cnt_ >=3) //28/06/2005;6am
          //if (th_rtt_incr_cnt_ >=4) //10/07/2005;09.35pm X
          //if (th_rtt_incr_cnt_ >=3) //11/07/2005;07.50am X
          //if (th_rtt_incr_cnt_ >=5) //11/07/2005;07.50am X
          {
              //if ((th_rtt_incr_cnt_ %3)==0) X
              //if ((th_rtt_incr_cnt_ %5)==0) //11/07/2005;07.50am
              //if ((th_rtt_incr_cnt_ %3)==0) //11/07/2005;06.53pm
              //if ((th_rtt_incr_cnt_ %4)==0) //11/07/2005;07.50am
              //if ((th_rtt_incr_cnt_ %5)==0) //15/07/2005;08.20pm
              //if ((th_rtt_incr_cnt_ %6)==0) //21/07/2005;09.50pm
              if ((spDest->tzCB.th_rtt_incr_cnt_ %7)==0) //21/07/2005;09.50pm
            {
                //spDest->tzCB.tz_tr_incclamp_ = min(spDest->tzCB.tz_tr_incclamp_+1,1);
                //spDest->tzCB.tz_tr_decclamp_ = min(spDest->tzCB.tz_tr_decclamp_+1,-2);
                //spDest->tzCB.tz_tr_incclamp_ = min(spDest->tzCB.tz_tr_incclamp_+1,2); //15/07/2005
                //spDest->tzCB.tz_tr_decclamp_ = min(spDest->tzCB.tz_tr_decclamp_+1,-3);
                spDest->tzCB.tz_tr_incclamp_ = min(spDest->tzCB.tz_tr_incclamp_+1,3); //15/07/2005 09.50pm
                spDest->tzCB.tz_tr_decclamp_ = min(spDest->tzCB.tz_tr_decclamp_+1,-4);


                //spDest->tzCB.tz_tr_incclamp_ = min(spDest->tzCB.tz_tr_incclamp_+1,0);
                //spDest->tzCB.tz_tr_decclamp_ = min(spDest->tzCB.tz_tr_decclamp_+1,-2);

            }

          }
          //spDest->tzCB.tz_rtt_cnt_ = 0; //17/06/2005;8pm
          //spDest->tzCB.tz_rtt_cnt_ = -3; //20/06/2005;9.45pm
          //spDest->tzCB.tz_rtt_cnt_ = -4; //20/06/2005;10.58pm
          //spDest->tzCB.tz_rtt_cnt_ = -3; //19/06/2005;9.09pm
          //spDest->tzCB.tz_rtt_cnt_ -=1; //19/06/2005;10.26pm
          //spDest->tzCB.tz_rtt_cnt_ = -1; //16/06/2005;8am
          //}
      }
      else
      //if (last_rtt_thresh_prob_ != 0 || (spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_ > spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_pprtt_>0) )
      //if (last_rtt_thresh_prob_ != 0 || spDest->tzCB.tz_rtt_cnt_ < -1) //(spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_ > spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_pprtt_>0) )
      //if (last_rtt_thresh_prob_ != 0 && spDest->tzCB.tz_rtt_cnt_ < -1) //(spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_ > spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_pprtt_>0) )
      //if (spDest->tzCB.tz_rtt_cnt_ < -2) //(spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_ > spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_pprtt_>0) )
      //if (spDest->tzCB.tz_rtt_cnt_ < -1) //(spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_prtt_ > spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_pprtt_>0) )
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>5) //14/04/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>15) //14/04/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>30) //14/04/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>20) //14/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>15) //14/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>10) //14/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>7) //14/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>5) //14/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>3) //14/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -3 && th_rtt_incr_cnt_>3) //16/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>5) //16/05/2005
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && th_rtt_incr_cnt_>7) //16/05/2005 X
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.2)) //17/05/2005 9.20am
      //if (spDest->tzCB.tz_rtt_cnt_ < -3 && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.2)) //17/05/2005 8pm
      //if (spDest->tzCB.tz_rtt_cnt_ < -2 && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.2)) //17/05/2005 9.40pm
      //if (spDest->tzCB.tz_rtt_cnt_ < -3 && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.2)) //17/05/2005 9.40pm
      //if (spDest->tzCB.tz_rtt_cnt_ < -3 && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.3)) //18/05/2005 10.00pm
      //if (spDest->tzCB.tz_rtt_cnt_ < -3 && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.4)) //18/05/2005 10.15pm
      //if (spDest->tzCB.tz_rtt_cnt_ < -3) // && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.4)) //19/05/2005 7.40am
      //if (spDest->tzCB.tz_rtt_cnt_ < -2) // && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.4)) //19/05/2005 9.05pm
      //if (spDest->tzCB.tz_rtt_cnt_ < -3 && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.5)) //19/05/2005 7.00am
      //if (spDest->tzCB.tz_rtt_cnt_ < -1) // && spDest->tzCB.tz_rtt_thresh_>(spDest->tzCB.tz_min_rtt_*1.4)) //06/06/2005 8.00am
      //if ((spDest->tzCB.tz_rtt_cnt_ < -2)  && spDest->tzCB.tz_rtt_thresh_>=(spDest->tzCB.tz_min_rtt_*1.15)) //18/06/2005 8.51pm
      //if ((spDest->tzCB.tz_rtt_cnt_ < -4)  && spDest->tzCB.tz_rtt_thresh_>=(spDest->tzCB.tz_min_rtt_*1.15)) //19/06/2005 8.28am
      //if ((spDest->tzCB.tz_rtt_cnt_ <= -5)  && spDest->tzCB.tz_rtt_thresh_>=(spDest->tzCB.tz_min_rtt_*1.15)) //19/06/2005 8.51pm
      //if ((spDest->tzCB.tz_rtt_cnt_ <= -5)  && spDest->tzCB.tz_rtt_thresh_>=(spDest->tzCB.tz_min_rtt_*1.15)) //21/06/2005 04.41pm
      //if ((spDest->tzCB.tz_rtt_cnt_ <= -6)  && spDest->tzCB.tz_rtt_thresh_>=(spDest->tzCB.tz_min_rtt_*1.15)) //20/06/2005 10.13pm
    if (spDest->tzCB.tz_rtt_cnt_ <= spDest->tzCB.tz_tr_decclamp_) //21/06/2005;8.18pm
      {
          //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_ * 0.95,orgin_rtt_thresh_); //Decrease By 5 % subject to minimum of Orginal rtt thresh
          //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_ * 0.90,orgin_rtt_thresh_); //14/04/05
          //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_ ,spDest->tzCB.tz_max_rtt_) * 0.90; //14/04/05;commented on 17/05/2005;8.15pm
          //if (mflag) //16/06/2005 1.40pm
          //{
              spDest->tzCB.last_rtt_thresh_prob_--;
          spDest->tzCB.th_rtt_decr_cnt_++; //14/04/2005
              //rtt_thresh_prob_ = 0; //on 14/04/2005;off on 19/05/2005;8.20pm
          spDest->tzCB.rtt_thresh_prob_ ++; //19/05/2005;8.40pm
          //if (rtt_thresh_prob_>4)
          //if (rtt_thresh_prob_>5) //20/05/2005;8.20am
          //if (rtt_thresh_prob_>6) //20/05/2005;8.51pm
          //if (rtt_thresh_prob_>4) //05/06/2005;8.51pm
          //if (rtt_thresh_prob_>2) //06/06/2005;8.51am
          //if (rtt_thresh_prob_>4) //06/06/2005;8.51am
          //if (rtt_thresh_prob_>6) //06/06/2005;8.51am
          //if (rtt_thresh_prob_>10) //16/06/2005;8.51am

          //if (rtt_thresh_prob_>15) //16/06/2005;8.51am
          //if (rtt_thresh_prob_>10) //17/06/2005;9.51pm
          //if (rtt_thresh_prob_>15) //19/06/2005;8.51pm
          //if (rtt_thresh_prob_>10) //19/06/2005;11.26pm; so far best at this
          //if (rtt_thresh_prob_>9) //20/06/2005;9.43am
          //if (rtt_thresh_prob_>8) //20/06/2005;9.43am
          //if (rtt_thresh_prob_>7) //20/06/2005;9.43am
          //if (rtt_thresh_prob_>6) //20/06/2005;9.43am
          //if (rtt_thresh_prob_>5) //20/06/2005;9.43am
          //if (rtt_thresh_prob_>4) //20/06/2005;10.30am
          //if (rtt_thresh_prob_>3) //20/06/2005;4.24pm
          //if (rtt_thresh_prob_>2) //20/06/2005;4.24pm
          //if (rtt_thresh_prob_>1) //20/06/2005;7.14pm
          //if (rtt_thresh_prob_>=3) //20/06/2005;8.05pm (same as '>2')

          //spDest->tzCB.tz_rtt_thresh_ = (spDest->tzCB.tz_rtt_thresh_ +spDest->tzCB.tz_artt_)/2; //15/05/2005 8pm;Very New
          //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_ ,spDest->tzCB.tz_artt_); //16/05/05
          //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.90 ,spDest->tzCB.tz_artt_); //17/05/05;8.15pm
          //spDest->tzCB.tz_rtt_thresh_ = (spDest->tzCB.tz_rtt_thresh_ +spDest->tzCB.tz_artt_)/2; //17/05/2005 8pm;8.30pm
          //spDest->tzCB.tz_rtt_thresh_ = (spDest->tzCB.tz_rtt_thresh_*0.9 +spDest->tzCB.tz_artt_)/2; //18/05/2005 9.35pm
          //spDest->tzCB.tz_rtt_thresh_ = (spDest->tzCB.tz_rtt_thresh_ +spDest->tzCB.tz_artt_)*0.9/2; //19/05/2005 7.10am
          //spDest->tzCB.tz_rtt_thresh_ = (spDest->tzCB.tz_rtt_thresh_ +spDest->tzCB.tz_max_rtt_)/2; //17/05/2005 8pm;8.30pm
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.95; //19/05/05;7.20am
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.97; //19/05/05;9.25pm
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0-0.70*spDest->tzCB.tz_min_rtt_); //19/05/2005; 9.40pm New
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0-0.50*spDest->tzCB.tz_min_rtt_); //19/05/2005; 9.55pm New
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0-0.30*spDest->tzCB.tz_min_rtt_); //19/05/2005; 10.10pm New
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0-0.20*spDest->tzCB.tz_min_rtt_); //19/05/2005; 10.20pm New
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0-0.30*spDest->tzCB.tz_min_rtt_); //20/05/2005;8.20am
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0-0.20*spDest->tzCB.tz_min_rtt_); //20/05/2005;8.51pm
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*(1.0-0.30*spDest->tzCB.tz_min_rtt_); //22/05/2005;1.40pm
          //orgin_rtt_thresh_ =orgin_rtt_thresh_*0.99; //12/06/2005;8.04am
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.99; //13/06/2005;8.04am
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.95; //16/06/2005;9.47pm
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.99; //17/06/2005;8.04am
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.95; //18/06/2005;8.am
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.90; //18/06/2005;7.16pm
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.95; //19/06/2005;1.15pm
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.97; //19/06/2005;1.15pm
         
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.10/max(rtt_thresh_prob_,1))); //20/06/2005;11.51pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.09/max(rtt_thresh_prob_,1))); //20/06/2005;11.51pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.08/max(rtt_thresh_prob_,1))); //21/06/2005;06.55am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.07/max(rtt_thresh_prob_,1))); //21/06/2005;06.55am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.06/max(rtt_thresh_prob_,1))); //21/06/2005;06.55am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.04/max(rtt_thresh_prob_,1))); //23/06/2005;09.13pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.06/max(rtt_thresh_prob_,1))); //24/06/2005;09.13pm New X
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.08/max(rtt_thresh_prob_,1))); //26/06/2005;10.28pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.10/max(rtt_thresh_prob_,1))); //26/06/2005;10.28pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.12/max(rtt_thresh_prob_,1))); //26/06/2005;10.28pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.14/max(rtt_thresh_prob_,1))); //26/06/2005;10.28pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.16/max(rtt_thresh_prob_,1))); //27/06/2005;5.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.06/max(rtt_thresh_prob_,1))); //28/06/2005;5.49am New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.07/max(rtt_thresh_prob_,1))); //03/07/2005;8.30pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.08/max(rtt_thresh_prob_,1))); //03/07/2005;09.20pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.09/max(rtt_thresh_prob_,1))); //03/07/2005;09.20pm New
          //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0-(0.06/max(rtt_thresh_prob_,1))); //06/07/2005;09.20pm New
          //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.06/max(rtt_thresh_prob_,1))),orgin_rtt_thresh_); //12/07/2005;08.04am New XX
          spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.06/max(spDest->tzCB.th_rtt_decr_cnt_,1))),spDest->tzCB.orgin_rtt_thresh_); //13/07/2005;05.54pm New
          //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.05/max(rtt_thresh_prob_,1))),orgin_rtt_thresh_); //13/07/2005;08.04am New
          //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.045/max(rtt_thresh_prob_,1))),orgin_rtt_thresh_); //13/07/2005;08.04am New
          //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.040/max(rtt_thresh_prob_,1))),orgin_rtt_thresh_); //13/07/2005;08.04am New
                                          //it starts from 0.95 as here rtt_thresh_prob_'s min. value is '2'
          //if (rtt_thresh_prob_>=5) //21/06/2005;12.04am (same as '>4')
          //if (rtt_thresh_prob_>=3) //21/06/2005;06.04am (same as '>2')
          //if (rtt_thresh_prob_>=5) //21/06/2005;07.04am (same as '>4')
          //if (rtt_thresh_prob_>=3) //21/06/2005;07.04am (same as '>4')
          //if (rtt_thresh_prob_>=2) //21/06/2005;07.04am (same as '>4')
          //if (rtt_thresh_prob_>=5) //21/06/2005;07.04am (same as '>4')
          //if (rtt_thresh_prob_>=3) //21/06/2005;07.04am (same as '>4')
          //if (rtt_thresh_prob_>=4) //21/06/2005;07.04am (same as '>4')
          //if (rtt_thresh_prob_>=6) //23/06/2005;09.39pm (same as '>4')
          //if (rtt_thresh_prob_>=2) //26/06/2005;09.39pm (same as '>4')
          //if (rtt_thresh_prob_>=1) //26/06/2005;09.39pm (same as '>4')
          //if (rtt_thresh_prob_>=5) //26/06/2005;09.39pm (same as '>4')
          //if (rtt_thresh_prob_>=7) //26/06/2005;07.39pm (same as '>4')X
          //if (rtt_thresh_prob_>=10) //26/06/2005;08.04pm (same as '>4')
          //if (rtt_thresh_prob_>=9) //26/06/2005;08.04pm (same as '>4')
          //if (rtt_thresh_prob_>=8) //26/06/2005;08.04pm (same as '>4')
          //if (rtt_thresh_prob_>=6) //26/06/2005;08.04pm (same as '>4')
          //if (rtt_thresh_prob_>=7) //26/06/2005;08.04pm (same as '>4')
          //if (rtt_thresh_prob_>=12) //27/06/2005;05.54am (same as '>4')
          if (spDest->tzCB.rtt_thresh_prob_>=20) //27/06/2005;05.54am (same as '>4')
          //if (rtt_thresh_prob_>=7) //28/06/2005;06.54am (same as '>4') XX
          //if (rtt_thresh_prob_>=8) //12/07/2005;08.14am (same as '>4')
          //if (rtt_thresh_prob_>=9) //12/07/2005;08.14am (same as '>4')
          //if (rtt_thresh_prob_>=10) //12/07/2005;08.14am (same as '>4')XXXX
          {     
          spDest->tzCB.rtt_thresh_prob_ = 0; //19/05/2005;8.40pm
          spDest->tzCB.th_rtt_incr_cnt_ = 0; //13/07/2005 7.41pm
          spDest->tzCB.th_rtt_decr_cnt_ = 0; //13/07/2005 7.41pm
          /* 21/06/2005; 08.24pm */
          spDest->tzCB.tz_tr_decclamp_ = -12; //Orginal
          spDest->tzCB.tz_tr_incclamp_ = 10;
          //spDest->tzCB.tz_tr_decclamp_ = -10;//03/07/2005;09.50pm
          //spDest->tzCB.tz_tr_incclamp_ = 8;
          //spDest->tzCB.tz_tr_decclamp_ = -9;//09/07/2005;09.50pm
          //spDest->tzCB.tz_tr_incclamp_ = 7;
          //spDest->tzCB.tz_tr_decclamp_ = -14;//03/07/2005;09.50pm; X ;Commented on 11/07/2005
          //spDest->tzCB.tz_tr_incclamp_ = 12;
          //spDest->tzCB.tz_tr_decclamp_ = -16;//03/07/2005;09.50pm
          //spDest->tzCB.tz_tr_incclamp_ = 14;
          //spDest->tzCB.tz_tr_decclamp_ = -14; //Orginal 11/07/2005 9.20am
          //spDest->tzCB.tz_tr_incclamp_ = 10;
          //spDest->tzCB.tz_tr_decclamp_ = -15; //Orginal 11/07/2005 9.39am
          //spDest->tzCB.tz_tr_incclamp_ = 11;
        //spDest->tzCB.tz_tr_decclamp_(-12),spDest->tzCB.tz_tr_incclamp_(10),spDest->tzCB.tz_tr_incclamp_onzero_(0);// After probe is over
          //spDest->tzCB.tz_rtt_thresh_ = (spDest->tzCB.tz_rtt_thresh_ +spDest->tzCB.tz_artt_)/2; //07/07/2005 7.09am New;
          /*if (spDest->tzCB.tz_rtt_thresh_ < spDest->tzCB.tz_artt_) //07/07/2005 7.09am New;
            spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_artt_; //07/07/2005 7.41am New;
          */
          }
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.98; //19/06/2005;1.15pm
          //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.98; //19/06/2005;1.15pm
          //spDest->tzCB.tz_rtt_thresh_ = (orgin_rtt_thresh_ +spDest->tzCB.tz_artt_)/2; //19/05/2005 9.40pm New;Commented on 06/06/2005
          spDest->tzCB.tz_rtt_cnt_ = 0; //19/05/2005;8pm
          //spDest->tzCB.tz_rtt_cnt_ = -4; //20/06/2005;9.45pm
          //spDest->tzCB.tz_rtt_cnt_ = -4; //19/06/2005;9.10pm
          //spDest->tzCB.tz_rtt_cnt_ +=1; //19/06/2005;10.26pm
          //spDest->tzCB.tz_rtt_cnt_ = -4; //20/06/2005;10.58pm
          //}
      }
       
        if (tz_debug_>0)
        printf("Last RTT Thresh Prob %d ; RTT Thresh %f !\n",spDest->tzCB.last_rtt_thresh_prob_,spDest->tzCB.tz_rtt_thresh_);
   
    }
    /*14/06/2005:If the RTT Thresh Fixing was not right */
    else
          if (spDest->tzCB.rtt_thresh_prob_ == 0)
      {
          //if (spDest->tzCB.tz_rtt_cnt_ <= -15)//Best
          //if (spDest->tzCB.tz_rtt_cnt_ <= -17)
          //if (spDest->tzCB.tz_rtt_cnt_ <= -18)
          if (spDest->tzCB.tz_rtt_cnt_ <= spDest->tzCB.tz_tr_decclamp_)
          {
              spDest->tzCB.th_rtt_decr_cnt_++; //13/07/2005 7.41pm
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.97; //14/06/2005;9.32am
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.98; //15/06/2005;9.32am
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*0.90; //18/06/2005;7.49pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.90,orgin_rtt_thresh_); //07/07/2005;7.49pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.94,orgin_rtt_thresh_); //07/07/2005;9.29pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.98,orgin_rtt_thresh_); //07/07/2005;9.29pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.96,orgin_rtt_thresh_); //09/07/2005;9.29pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.95,orgin_rtt_thresh_); //09/07/2005;9.29pm
              //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.06/max(th_rtt_decr_cnt_,1))),orgin_rtt_thresh_); //13/07/2005;07.43pm New
              //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.08/max(th_rtt_decr_cnt_,1))),orgin_rtt_thresh_); //13/07/2005;07.43pm New
              //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.07/max(th_rtt_decr_cnt_,1))),orgin_rtt_thresh_); //13/07/2005;07.43pm New
              //spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.10/max(th_rtt_decr_cnt_,1))),orgin_rtt_thresh_); //13/07/2005;07.43pm New
              spDest->tzCB.tz_rtt_thresh_ =max(spDest->tzCB.tz_rtt_thresh_*(1.0-(0.12/max(spDest->tzCB.th_rtt_decr_cnt_,1))),spDest->tzCB.orgin_rtt_thresh_); //15/07/2005;08.20pm New
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.94,orgin_rtt_thresh_); //09/07/2005;9.29pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.93,orgin_rtt_thresh_); //09/07/2005;9.29pm X
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.90,orgin_rtt_thresh_); //11/07/2005;10.10am
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.85,orgin_rtt_thresh_); //11/07/2005;06.15pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.80,orgin_rtt_thresh_); //11/07/2005;06.15pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.92,orgin_rtt_thresh_); //09/07/2005;9.29pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.91,orgin_rtt_thresh_); //09/07/2005;9.29pm
              //spDest->tzCB.tz_rtt_thresh_ = max(spDest->tzCB.tz_rtt_thresh_*0.90,orgin_rtt_thresh_); //09/07/2005;9.29pm
              spDest->tzCB.tz_rtt_cnt_ = 0;
            spDest->tzCB.tz_tr_decclamp_ = spDest->tzCB.tz_tr_decclamp_ - 1;
            //spDest->tzCB.tz_tr_incclamp_ = max(spDest->tzCB.tz_tr_incclamp_ - 1,10);
            spDest->tzCB.tz_tr_incclamp_ = max(spDest->tzCB.tz_tr_incclamp_ - 1,5);//Commented on 11/07/2005 10.26am
          }
          //15/06/2005
          if (spDest->tzCB.tz_rtt_cnt_ >= spDest->tzCB.tz_tr_incclamp_)
          {
              spDest->tzCB.th_rtt_incr_cnt_++; //13/07/2005 7.41pm
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.01; //15/06/2005;9.32am
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.02; //15/06/2005;9.32am
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.10; //18/06/2005;7.56pm
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.05; //18/06/2005;11.29pm
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.02; //07/07/2005;09.29pm
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.01; //08/07/2005;09.29pm
              //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.01/max(th_rtt_incr_cnt_,1))); //13/07/2005;08.00pm New
              //spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.02/max(th_rtt_incr_cnt_,1))); //13/07/2005;08.00pm New
              spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thresh_*(1.0+(0.015/max(spDest->tzCB.th_rtt_incr_cnt_,1))); //13/07/2005;08.00pm New
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.005; //11/07/2005;09.29pm
              //spDest->tzCB.tz_rtt_thresh_ = spDest->tzCB.tz_rtt_thresh_*1.02; //09/07/2005;09.29pm
              spDest->tzCB.tz_rtt_cnt_ = 0;
            spDest->tzCB.tz_tr_incclamp_ = spDest->tzCB.tz_tr_incclamp_ + 1;
            //spDest->tzCB.tz_tr_decclamp_ = min(spDest->tzCB.tz_tr_decclamp_ + 1,-10);
            //spDest->tzCB.tz_tr_decclamp_ = min(spDest->tzCB.tz_tr_decclamp_ + 1,-5);
            spDest->tzCB.tz_tr_decclamp_ = min(spDest->tzCB.tz_tr_decclamp_ + 1,-7);//Commented on 11/07/2005 10.26am
          }
      }         

}

/* To distinguish loss due to corruption and congestion
* 02/06/2004 */
int TezpurSctpAgent::TzCongested(SctpDest_S *spDest)
{
// Returns 1 if the loss was due to congestion else 0
   
      if (tz_WinIncrOpt_==6 || tz_WinIncrOpt_==2 || tz_WinIncrOpt_==7)   
        return 0;        //28/02/2005     
      else
    return 1;
      /*cwnd_ =spDest->iCwnd /2;
      if (cwnd_<1)
          spDest->iCwnd = 1;
      return 0;        //14/06/2004     
        */
      //return spDest->tzCB.tz_cong_flag_; //i. 08/06/2004
    if (spDest->tzCB.tz_cong_flag_ == 0)
        {
        //if (spDest->tzCB.tz_artt_ >= ((spDest->tzCB.tz_rtt_thresh_*2)/3))
        //if (spDest->tzCB.tz_artt_ >= spDest->tzCB.tz_rtt_thresh_)

        //1. if(spDest->tzCB.tz_crtt_ >= spDest->tzCB.tz_rtt_thresh_ || spDest->tzCB.tz_prtt_ >=spDest->tzCB.tz_rtt_thresh_)
        //2.if((spDest->tzCB.tz_crtt_ >= (spDest->tzCB.tz_rtt_thresh_/2)) && (spDest->tzCB.tz_crtt_>=spDest->tzCB.tz_prtt_ ))
        //3.if (spDest->tzCB.tz_artt_ >= (spDest->tzCB.tz_rtt_thresh_/2)) //AVG OF 3 RTTs
        //4.if (spDest->tzCB.tz_artt_ >= (spDest->tzCB.tz_rtt_thresh_/2)) //Avg of 5 RTTs
        //5.if ((spDest->tzCB.tz_artt_ >= (spDest->tzCB.tz_rtt_thresh_/2)) || ((spDest->tzCB.tz_crtt_ >= (spDest->tzCB.tz_rtt_thresh_/2)) && (spDest->tzCB.tz_crtt_>=spDest->tzCB.tz_prtt_ ))) //Avg of 5 RTTs 5.
        //6.if ((spDest->tzCB.tz_artt_ >= (spDest->tzCB.tz_rtt_thresh_*2/3)) || ((spDest->tzCB.tz_crtt_ >= (spDest->tzCB.tz_rtt_thresh_*2/3)) && (spDest->tzCB.tz_crtt_>=spDest->tzCB.tz_prtt_ ))) //Avg of 5 RTTs 6.
    //7.if ((spDest->tzCB.tz_artt_ >= (spDest->tzCB.tz_rtt_thresh_*2/3)) || (spDest->tzCB.tz_prtt_>=spDest->tzCB.tz_crtt_  && spDest->tzCB.tz_pprtt_>=spDest->tzCB.tz_prtt_)) //Avg of 5 RTTs 7.
    //if ((spDest->tzCB.tz_artt_ >= (spDest->tzCB.tz_rtt_thresh_/2)) && (spDest->tzCB.tz_prtt_>=spDest->tzCB.tz_crtt_  || spDest->tzCB.tz_pprtt_>=spDest->tzCB.tz_prtt_)) //Avg of 5 RTTs 8.
        //if (spDest->tzCB.tz_artt_ >= (spDest->tzCB.tz_rtt_thresh_/2)) //ii.Avg of 3 RTTs 08/06/2004
        //if (spDest->tzCB.tz_cwndincr_ <= 0) //iii. 08/06/2004
        //if ((spDest->tzCB.tz_artt_ > (spDest->tzCB.tz_rtt_thresh_*2/3)) || (spDest->tzCB.tz_cwndincr_ < 0))//commented on 22/06/2004
            //iv.Avg of 3 RTTs  08/06/2004
        //if ((spDest->tzCB.tz_artt_ > (spDest->tzCB.tz_rtt_thresh_*3/5)) || (spDest->tzCB.tz_cwndincr_ < 0))
            //v.Avg of 5 RTTs  08/06/2004
        //if ((spDest->tzCB.tz_artt_ > (spDest->tzCB.tz_rtt_thresh_*2/3)) || (spDest->tzCB.tz_cwndincr_ < 0) || (spDest->tzCB.tz_crtt_>(spDest->tzCB.tz_rtt_thresh_/2) && spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_))
        //if ((spDest->tzCB.tz_artt_ > (spDest->tzCB.tz_rtt_thresh_*2/3)) || (spDest->tzCB.tz_cwndincr_ < 0) || (spDest->tzCB.tz_prtt_>spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_))
            //vi.Avg of 3 RTTs  08/06/2004
        //if ((spDest->tzCB.tz_artt_ > (spDest->tzCB.tz_rtt_thresh_/2)) || (spDest->tzCB.tz_cwndincr_ < 0) || (spDest->tzCB.tz_prtt_>spDest->tzCB.tz_pprtt_ && spDest->tzCB.tz_crtt_ > spDest->tzCB.tz_prtt_) ||spDest->iCwnd>(spDest->tzCB.tz_cwnd_max_+spDest->tzCB.tz_mxrtt_cwnd_)/2 || spDest->tzCB.tz_crtt_>(spDest->tzCB.tz_max_rtt_+spDest->tzCB.tz_mxcwnd_rtt_)/2)
            //vii.Avg of 3 RTTs  08/06/2004
        if(((spDest->tzCB.tz_crtt_ > (spDest->tzCB.tz_rtt_thresh_*2/3)) && (spDest->tzCB.tz_crtt_>spDest->tzCB.tz_prtt_ ) && spDest->tzCB.tz_prtt_>0) || (spDest->tzCB.tz_crtt_>spDest->tzCB.tz_rtt_thresh_ ))
            return 1;
        else
            return 0;
    }
  else
      /*    {
        //12/06/2004
          //if (spDest->tzCB.tz_rtt_abrupt_ ==1 or spDest->tzCB.tz_crtt_<spDest->tzCB.tz_rtt_thresh_*3/5) //iii.
          if (spDest->tzCB.tz_rtt_abrupt_ ==1 or spDest->tzCB.tz_crtt_<spDest->tzCB.tz_rtt_thresh_/2)
          return 0;
      else
          return 1;
  }*/
      return spDest->tzCB.tz_cong_flag_;

//if (spDest->tzCB.tz_slow_cnt_>1)
  // return 1;

//return -1;

/*
//if( spDest->tzCB.tz_prev_cwnd2_>0)
  //if (spDest->tzCB.tz_prev_cwnd1_>spDest->tzCB.tz_prev_cwnd2_ && spDest->tzCB.tz_crtt_>spDest->tzCB.tz_prtt_)
  if (spDest->tzCB.tz_crtt_>spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_cwndincr_<0)
      return 2; //congestion was there
  else
  if (spDest->tzCB.tz_crtt_<spDest->tzCB.tz_prtt_ && spDest->tzCB.tz_cwndincr_>0)
      return -1; //No congestion
  //if (spDest->tzCB.tz_prev_cwnd1_<spDest->tzCB.tz_prev_cwnd2_ && spDest->tzCB.tz_crtt_<spDest->tzCB.tz_prtt_)

    return 1; //i.e. we can't say whether congestion was there or not
  //if (spDest->tzCB.tz_cwndincr_<=0 )
  //if (spDest->tzCB.tz_crtt_ >= spDest->tzCB.tz_prtt_ && (spDest->tzCB.tz_rtt_thresh_ - spDest->tzCB.tz_crtt_) <= spDest->tzCB.tz_alpha_)
  //      return 1;
*/
  // return -1;
//Disabled on 29/04/2003
//Enabled on 14/05/2003
//Disabled on 15/05/2003

}
double TezpurSctpAgent::TzGetCwndIncr(SctpDest_S *spDest)
    //RTT Based Technique (2001-2002)
{
//It is based on RTT

      //if (cwnd_<=1)
        // return 1;
        //printf("2.spDest->tzCB.tz_slowdown=%d  ",spDest->tzCB.tz_sldown_);


    //RTT RATIO
    //if (spDest->tzCB.tz_pprtt_==1 || spDest->tzCB.tz_pprtt_==2) //offed on 12/06/2003
          //  return 0;                //27/05/2003
             
    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/spDest->tzCB.tz_rtt_thresh_; //new 14/06/2004
    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/min(spDest->tzCB.tz_crtt_,spDest->tzCB.tz_rtt_thresh_); //13/03/2005
    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/max(spDest->tzCB.tz_crtt_,spDest->tzCB.tz_rtt_thresh_); //new - Commented on 02/05/2005
    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/min(spDest->tzCB.tz_crtt_,spDest->tzCB.tz_rtt_thresh_); //27/05/2005
  /*if (tz_WinIncrOpt_==9) // || tz_WinIncrOpt_ == 3) //26/05/2005
  {
    if (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_min_rtt_>0)
        return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/(spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_min_rtt_); //02/05/2005
    else
        return 0.5; // 1;
  }
  else*/
    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/max(spDest->tzCB.tz_max_rtt_,spDest->tzCB.tz_rtt_thresh_); //Preserving the Old Technique- 26/05/2005
    return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/max(spDest->tzCB.tz_crtt_,spDest->tzCB.tz_rtt_thresh_); //Preserving the Old Technique- 26/05/2005
    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/spDest->tzCB.tz_rtt_thresh_; //- 26/05/2005

    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/((spDest->tzCB.tz_crtt_+spDest->tzCB.tz_rtt_thresh_)/2); //new
    //return (spDest->tzCB.tz_rtt_thresh_-spDest->tzCB.tz_crtt_)/spDest->tzCB.tz_max_rtt_;

}
void TezpurSctpAgent::AdjustCwnd(SctpDest_S *spDest)  //opencwnd()
{ int j;
  //double i;
   
  //printf("TcpTezpur:mxcwnd=%d cwndincr=%f cwnd= %d Tz_Slow_Count= %d PeerRwnd=%d!\n",(int)spDest->tzCB.tz_cwnd_max_,spDest->tzCB.tz_cwndincr_,spDest->iCwnd,spDest->tzCB.tz_slow_cnt_,uiPeerRwnd);
  if (tz_WinIncrOpt_==9) //26/05/2005
    TzComputeRTTThresh(spDest); //23/03/2005

  //spDest->tzCB.tz_prev_cwnd2_ = spDest->tzCB.tz_prev_cwnd1_;
  //spDest->tzCB.tz_prev_cwnd1_ =spDest->iCwnd;
  if (spDest->tzCB.tz_cwnd_max_ <spDest->iCwnd)
      {
      spDest->tzCB.tz_cwnd_max_ =spDest->iCwnd;
      //spDest->tzCB.tz_mxcwnd_rtt_ = spDest->tzCB.tz_crtt_;
      }
  //j=window();
/*    if (spDest->tzCB.tz_sldown_==1)
          {
          //printf("3.spDest->tzCB.tz_slowdown=%d  ",spDest->tzCB.tz_sldown_);
            spDest->tzCB.tz_sldown_=0;
          cwnd_ =1;
            //return (-1)*(2*cwnd_/3);
          }
  else
  {*/
  if (tz_WinIncrOpt_ == 3 || tz_WinIncrOpt_ == 9 || tz_WinIncrOpt_ == 10) {
    //if (spDest->tzCB.tz_rtt_abrupt_==0)  //Change cwnd only when RTT is not abrupt 12/06/2004

        spDest->tzCB.tz_cwndincr_ = TzGetCwndIncr(spDest); //RTT Based
     
      //if (spDest->tzCB.tz_cwndincr_<0 && spDest->tzCB.tz_cong_flag_ == 0)
    //    spDest->tzCB.tz_cwndincr_ = spDest->tzCB.tz_cwndincr_*5.0;
  } 
  /*
else
    if (tz_WinIncrOpt_ == 1)
    {   
        spDest->tzCB.tz_cwndincr_ = min(spDest->tzCB.tz_max_cwndincr_,spDest->tzCB.tz_get_cwnd_incr_qdelay()); //Queuing Delay Based
        //spDest->tzCB.tz_cwndincr_ = spDest->tzCB.tz_get_cwnd_incr_qdelay();
        if (spDest->tzCB.tz_cwndincr_<0)
          spDest->tzCB.tz_cwndincr_ = max((0-spDest->tzCB.tz_max_cwndincr_),spDest->tzCB.tz_get_cwnd_incr_qdelay()); //Queuing Delay Based

    } 
else
  if (tz_WinIncrOpt_ == 2 || tz_WinIncrOpt_ == 6 || tz_WinIncrOpt_ == 7)
        spDest->tzCB.tz_cwndincr_ = spDest->tzCB.tz_get_cwnd_incr_aceb();     //ACEB Based;11/02/2005
        //spDest->tzCB.tz_cwndincr_ = 20 ; //spDest->tzCB.tz_get_cwnd_incr_aceb();     //ACEB Based;11/02/2005
*/
  //03/08/2005
 
  /*if (tz_WinIncrOpt_ == 2)
        spDest->tzCB.tz_cwndincr_ = spDest->tzCB.tz_get_cwnd_incr_aceb()-cwnd_;     //ACEB Based;26/12/2003
        //return (spDest->tzCB.tz_FwMin_ -spDest->iCwnd); //09/02/2005
  if (tz_WinIncrOpt_ == 6)
        spDest->tzCB.tz_cwndincr_ = (spDest->tzCB.tz_get_cwnd_incr_aceb()*spDest->tzCB.tz_artt_)/size_;     //Available Bandwidth Based;11/02/2005
        //return (spDest->tzCB.tz_FwMin_*spDest->tzCB.tz_artt_)/size_;//02/02/2005
    */
 
  /*
  else
    if (tz_WinIncrOpt_ == 4)
        spDest->tzCB.tz_cwndincr_ = spDest->tzCB.tz_get_cwnd_incr_tql();     //TQL Based;29/01/2004
  else
    if (tz_WinIncrOpt_ == 5)
      spDest->tzCB.tz_cwndincr_ = min(spDest->tzCB.tz_max_cwndincr_,spDest->tzCB.tz_get_rfcwnd_incr()); //RTT Based+Some Refined Technique 16th May 2004
*/
  //03/08/2005

//if (tz_debug_ > 0)
//printf ("\n\nCurrent QDelay= %f Remaining Delay = %f EstMax Qdelay= %f Max Qdelay= %f Th Q Delay= %f Cwnd Incr = %f \n",spDest->tzCB.tz_qdelay_,(spDest->tzCB.tz_crtt_-spDest->tzCB.tz_qdelay_),spDest->tzCB.tz_estmax_qdelay_,spDest->tzCB.tz_max_qdelay_,spDest->tzCB.tz_qdelay_thresh_,spDest->tzCB.tz_cwndincr_);
 
  /*if (i<=0)
  {
        spDest->tzCB.tz_slow_cnt_ +=1;
   
          if (spDest->tzCB.tz_slow_cnt_<=1)
          {
            spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_min_rtt_+(spDest->tzCB.tz_max_rtt_-spDest->tzCB.tz_min_rtt_)/3;
            //cwnd_ = 3*cwnd_/4;
          spDest->iCwnd +=i;
            }
          //else
            // spDest->tzCB.tz_rtt_thresh_ =spDest->tzCB.tz_rtt_thper_*spDest->tzCB.tz_rtt_thresh_/100;
          //cwnd_ = 3*cwnd_/4;
    }
  else*/
  //if (cwnd_>ssthresh_ && i>0)
  //spDest->iCwnd+=1/cwnd_;
  //else
  //if (i>1)
  // i=1;
  /*if (spDest->tzCB.tz_cwndincr_<0 && spDest->tzCB.tz_crtt_>spDest->tzCB.tz_prtt_)
    spDest->iCwnd +=min(spDest->tzCB.tz_cwndincr_,-0.5);      //we are seeing more congestions
  else */

  /*if (tz_WinIncrOpt_ == 2 || tz_WinIncrOpt_ == 6 || tz_WinIncrOpt_ == 7)
    spDest->iCwnd = spDest->tzCB.tz_cwndincr_ ;
  else*/
  if(spDest->iOutstandingBytes >= spDest->iCwnd)
  {
      //printf("Newly Bytes Acked=%d    Max Data Size=%d !\n",spDest->iNumNewlyAckedBytes, uiMaxDataSize);
      //spDest->iCwnd += MIN(spDest->iNumNewlyAckedBytes, uiMaxDataSize); Orginal
          //u_int uiTmp = spDest->iNumNewlyAckedBytes;
          //u_int uiTmp = uiMaxDataSize;
          u_int uiTmp = min(spDest->iNumNewlyAckedBytes,uiMaxDataSize);
    if (tz_WinIncrOpt_ == 8)
      spDest->iCwnd = spDest->tzCB.tz_artt_*40*uiTmp;
    else
    if (tz_WinIncrOpt_==9) //26/05/2005; //Based on Dynamically Computed Threshold RTT
    {
    if (spDest->tzCB.tz_artt_>0)
  //Experimental for Fairness for long & short RTT Flows: 28/03/2005
      //cwnd_ += spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ;
      //cwnd_ += 2*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ;
      //cwnd_ += 2.5*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ;
      //cwnd_ += 2.25*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ;
      //cwnd_ += 3*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ;
      //cwnd_ += 10*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ;
      //cwnd_ += 2.25*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ;
      //cwnd_ += 2*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //14/04/2005
      //cwnd_ += 1.5*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //14/04/2005
      //cwnd_ += 5*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //14/04/2005
      //cwnd_ += 10*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //14/04/2005
      //cwnd_ += 1.25*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //14/04/2005
      //cwnd_ += spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //14/04/2005
      //cwnd_ +=0.8*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //14/04/2005
      //cwnd_ += 2.25*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += 1.5*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += 5*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += 2*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += 1.5*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      /*{
      if (rtt_thresh_prob_==1)*/
      //cwnd_ += 4*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += 0.80*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.50*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.250*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.20*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.15*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.1*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.05*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.075*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //03/05/2005
      //cwnd_ += 0.9*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //11/05/2005
      //cwnd_ += 0.50*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //16/05/2005 1pm
      //cwnd_ += 0.30*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //16/05/2005 1.30pm
      //cwnd_ += 0.50*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/05/2005 9.25am
      //cwnd_ += 1.0*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/05/2005 9.35am
      //cwnd_ += 0.90*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/05/2005 10.20am
      //cwnd_ += 0.80*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/05/2005 10.20am
      //cwnd_ += 0.50*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/05/2005 8.30pm
      //cwnd_ += 0.30*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/05/2005 8.55pm
      //cwnd_ += 0.40*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/05/2005 9pm
      //cwnd_ += 0.50*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //20/05/2005 9pm
      //cwnd_ += 0.60*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //20/05/2005 9.15pm XX
      //cwnd_ += 0.70*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //20/05/2005 9.25pm
      //cwnd_ += 0.80*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //20/05/2005 9.45pm
      //cwnd_ += 0.60*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //22/05/2005 12.45pm XX
      spDest->iCwnd += (spDest->tzCB.tz_cwndincr_*uiTmp) ;//05/06/2005
      //cwnd_ += 3*spDest->tzCB.tz_min_rtt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      //cwnd_ += 4*spDest->tzCB.tz_artt_*spDest->tzCB.tz_cwndincr_ ; //18/04/2005
      /*else
      spDest->iCwnd +=1;        //29/04/2005         
      }*/
    }
    else
/*  if (tz_WinIncrOpt_==10) //28/05/2005; //Changing 'cwnd' on every alternative RTT (as suggested by DKS)
  {
     
      //if ((spDest->tzCB.tz_count_ % 2)==0)
      //cwnd_ += spDest->tzCB.tz_cwndincr_ ;

        //cwnd_ += tz_round_cwndincr() ;
        double tmpcwnd = tz_round_cwndincr() ;
        spDest->iCwnd += tmpcwnd ; //tz_round_cwndincr() ;
        //printf("Cwnd Incr=%f; Rounded Cwnd Incr%f\n",spDest->tzCB.tz_cwndincr_,tmpcwnd);
  }
  else*/ //03/08/2005
    spDest->iCwnd += (spDest->tzCB.tz_cwndincr_*uiTmp) ;//For tz_WinIncrOpt_ ==3 only

 
      tiCwnd++; // trigger changes for trace to pick up
    }

   
  //Keeping cwnd well within wnd, which is being under examination now 08/01/2003
//If uiPeerRwnd is shared between concurrent paths, change tactics;
//For Failover Path i.e. using single path at a time this will work
//if (spDest->iCwnd > uiPeerRwnd) // spDest->tzCB.tz_shared_rwnd_)
//    spDest->iCwnd = uiPeerRwnd; //  spDest->tzCB.tz_shared_rwnd_;
   
    /*if (spDest->iCwnd <= 0)
              spDest->iCwnd = uiMaxDataSize; */
    /*22/08/2005*/
    //if (spDest->iCwnd < uiMaxDataSize)
          //    spDest->iCwnd = uiMaxDataSize;
    if (spDest->iCwnd < (iInitialCwnd*uiMaxDataSize))
              spDest->iCwnd = iInitialCwnd*uiMaxDataSize;
              //spDest->iCwnd = iInitialCwnd * uiMaxDataSize;

    if (tz_debug_>0)
  printf("TcpTezpur:mxcwnd=%d cwndincr=%f cwnd= %d Tz_Slow_Count= %d PeerRwnd=%d!\n",(int)spDest->tzCB.tz_cwnd_max_,spDest->tzCB.tz_cwndincr_,spDest->iCwnd,spDest->tzCB.tz_slow_cnt_,uiPeerRwnd);

    double now=Scheduler::instance().clock();
    if (tz_ftrace_)
        fprintf(tz_tracefd_,"%f    %f    %f    %f    %f    %f    %d\n",now,spDest->tzCB.tz_crtt_,spDest->tzCB.tz_rtt_thresh_,spDest->tzCB.tz_artt_,(double)(spDest->iCwnd/uiMaxDataSize),spDest->dRto,spDest->iNsAddr);
}

/*
void TezpurSctpAgent::newack(Packet *pkt)
{
    hdr_tcp *tcph = hdr_tcp::access(pkt);
    tz_senttime_ = tcph->ts_echo();

    //tz_ack_counter_ ++;
    //printf("\nsenttime =%f; ts = %f ts_echo = %f ",tcph->ts(),tcph->ts_echo(),tz_senttime_);
    //if (rtt_active_ && tcph->seqno()>=rtt_seq_ && !ts_option_)
    if (tz_debug_>0)
    printf("\ntz_prtt_seq =%d; rtt_seqno =%d; tcph_seq= %d;rtt_ts=%f;",tz_prtt_seq_,rtt_seq_,tcph->seqno(),rtt_ts_);
      tz_update_rtt(pkt);
      //tz_compute_rtt_thresh(); //21/03/2005
      tz_get_qdelay(pkt);
      tz_get_FW(pkt);
      tz_get_TQL(pkt);
      if ((tz_ack_counter_%2)==0)
      DataRateCal_Timeout();
      TcpAgent::newack(pkt);
}
*/


/* The Main Overloaded Methods other than 'Reset()' & 'AdjustCwnd()' */

  void TezpurSctpAgent::RttUpdate(double sTime, SctpDest_S *spDest)
{
    //printf("Test....Sctp-Tezpur Rtt Update \n");
    //TimestampSctpAgent::RttUpdate(sTime,spDest);
    SctpAgent::RttUpdate(sTime,spDest);
    TzUpdateRTTs(spDest);
        CheckPathStat();
    //AdjustCwnd(spDest);
    //printf("Test....Sctp-Tezpur RTTUpdate\n");
}

/* These methods are overloaded becuase these call the above overloaded methods */

void TezpurSctpAgent::SendBufferDequeueUpTo(u_int uiTsn)
{
  DBG_I(SendBufferDequeueUpTo);

  Node_S *spDeleteNode = NULL;
  Node_S *spCurrNode = sSendBuffer.spHead;
  SctpSendBufferNode_S *spCurrNodeData = NULL;
  Boolean_E eSkipRttUpdate = FALSE;

  /* Only the first TSN that is being dequeued can be used to reset the
  * error cunter on a destination. Why? Well, suppose there are some
  * chunks that were gap acked before the primary had errors. Then the
  * gap gets filled with a retransmission using an alternate path. The
  * filled gap will cause the cum ack to move past the gap acked TSNs,
  * but does not mean that the they can reset the errors on the primary.
  */
 
  iAssocErrorCount = 0;

  spCurrNodeData = (SctpSendBufferNode_S *) spCurrNode->vpData;

  /* trigger trace ONLY if it was previously NOT 0 */
  if(spCurrNodeData->spDest->iErrorCount != 0)
    {
      spCurrNodeData->spDest->iErrorCount = 0; // clear error counter
      tiErrorCount++;                          // ... and trace it too!
      spCurrNodeData->spDest->eStatus = SCTP_DEST_STATUS_ACTIVE;
      if(spCurrNodeData->spDest == spPrimaryDest &&
    spNewTxDest != spPrimaryDest)
    {
      DBG_PL(SendBufferDequeueUpTo,
        "primary recovered... migrating back from %p to %p"),
        spNewTxDest, spPrimaryDest DBG_PR;
      spNewTxDest = spPrimaryDest; // return to primary
    }
    }

  while(spCurrNode != NULL &&
    ((SctpSendBufferNode_S*)spCurrNode->vpData)->spChunk->uiTsn <= uiTsn)
    {
      spCurrNodeData = (SctpSendBufferNode_S *) spCurrNode->vpData;

      /* Only count this chunk as newly acked and towards partial bytes
      * acked if it hasn't been gap acked or marked as ack'd due to rtx
      * limit. 
      */
      if((spCurrNodeData->eGapAcked == FALSE) &&
    (spCurrNodeData->eAdvancedAcked == FALSE) )
    {
      spCurrNodeData->spDest->iNumNewlyAckedBytes
        += spCurrNodeData->spChunk->sHdr.usLength;

      /* only add to partial bytes acked if we are in congestion
      * avoidance mode and if there was cwnd amount of data
      * outstanding on the destination (implementor's guide)
      */
      if(spCurrNodeData->spDest->iCwnd >spCurrNodeData->spDest->iSsthresh &&
        ( spCurrNodeData->spDest->iOutstandingBytes
          >= spCurrNodeData->spDest->iCwnd) )
        {
          spCurrNodeData->spDest->iPartialBytesAcked
        += spCurrNodeData->spChunk->sHdr.usLength;
        }
    }


      /* This is to ensure that Max.Burst is applied when a SACK
      * acknowledges a chunk which has been fast retransmitted. If it is
      * ineligible for fast rtx, that can only be because it was fast
      * rtxed or it timed out. If it timed out, a burst shouldn't be
      * possible, but shouldn't hurt either. The fast rtx case is what we
      * are really after. This is a proposed change to RFC2960 section
      * 7.2.4
      */
      if(spCurrNodeData->eIneligibleForFastRtx == TRUE)
    eApplyMaxBurst = TRUE;


      // BEGIN -- Timestamp changes to this function

      /* We update the RTT estimate if the following hold true:
      *  1. Timestamp set for this chunk matches echoed timestamp
      *  2. This chunk has not been gap acked already
      *  3. This chunk has not been advanced acked (pr-sctp: exhausted rtxs)
      */
      if(fInTimestampEcho == (float) spCurrNodeData->dTxTimestamp &&
    spCurrNodeData->eGapAcked == FALSE &&
    spCurrNodeData->eAdvancedAcked == FALSE)
    {
      RttUpdate(spCurrNodeData->dTxTimestamp, spCurrNodeData->spDest);
    }

      // END -- Timestamp changes to this function

     
      /* if there is a timer running on the chunk's destination, then stop it
      */
      if(spCurrNodeData->spDest->eRtxTimerIsRunning == TRUE)
    StopT3RtxTimer(spCurrNodeData->spDest);

      spDeleteNode = spCurrNode;
      spCurrNode = spCurrNode->spNext;
      DeleteNode(&sSendBuffer, spDeleteNode);
      spDeleteNode = NULL;
    }

  DBG_X(SendBufferDequeueUpTo);
}

/* returns a boolean of whether a fast retransmit is necessary
*/
Boolean_E TezpurSctpAgent::ProcessGapAckBlocks(u_char *ucpSackChunk, Boolean_E eNewCumAck)
{
    //return SctpAgent::ProcessGapAckBlocks(ucpSackChunk, eNewCumAck);
//}

  DBG_I(ProcessGapAckBlocks);

  Boolean_E eFastRtxNeeded = FALSE;
  u_int uiHighestTsnNewlySacked = uiCumAckPoint; // fast rtx (impl guide v.02)
  u_int uiStartTsn;
  u_int uiEndTsn;
  Node_S *spCurrNode = NULL;
  SctpSendBufferNode_S *spCurrNodeData = NULL;
  Node_S *spCurrDestNode = NULL;
  SctpDest_S *spCurrDestNodeData = NULL;
  Boolean_E eFirstOutstanding = FALSE; 

  SctpSackChunk_S *spSackChunk = (SctpSackChunk_S *) ucpSackChunk;

  u_short usNumGapAcksProcessed = 0;
  SctpGapAckBlock_S *spCurrGapAck
    = (SctpGapAckBlock_S *) (ucpSackChunk + sizeof(SctpSackChunk_S));

  DBG_PL(ProcessGapAckBlocks,"CumAck=%d"), spSackChunk->uiCumAck DBG_PR;

  if(sSendBuffer.spHead == NULL) // do we have ANYTHING in the rtx buffer?
    {
      // This COULD mean that this sack arrived late, and a previous one
      // already cum ack'd everything. ...so, what do we do? nothing??
      //
    }
 
  else // we do have chunks in the rtx buffer
    {
      // make sure we clear all the eSeenFirstOutstanding flags before
      // using them! 
      //
      for(spCurrDestNode = sDestList.spHead;
      spCurrDestNode != NULL;
      spCurrDestNode = spCurrDestNode->spNext)
    {
      spCurrDestNodeData = (SctpDest_S *) spCurrDestNode->vpData;
      spCurrDestNodeData->eSeenFirstOutstanding = FALSE;
    }

      for(spCurrNode = sSendBuffer.spHead;
      (spCurrNode != NULL) &&
        (usNumGapAcksProcessed != spSackChunk->usNumGapAckBlocks);
      spCurrNode = spCurrNode->spNext)
    {
      spCurrNodeData = (SctpSendBufferNode_S *) spCurrNode->vpData;

      DBG_PL(ProcessGapAckBlocks, "eSeenFirstOutstanding=%s"),
        spCurrNodeData->spDest->eSeenFirstOutstanding ? "TRUE" : "FALSE"
        DBG_PR;
       
      // is this chunk the first outstanding on its destination?
      //
      if(spCurrNodeData->spDest->eSeenFirstOutstanding == FALSE &&
        spCurrNodeData->eGapAcked == FALSE &&
        spCurrNodeData->eAdvancedAcked == FALSE)
        {
          // yes, it is the first!
          //
          eFirstOutstanding = TRUE;
          spCurrNodeData->spDest->eSeenFirstOutstanding = TRUE;
        }
      else
        {
          // nope, not the first...
          //
          eFirstOutstanding = FALSE;
        }

      DBG_PL(ProcessGapAckBlocks, "eFirstOutstanding=%s"),
        eFirstOutstanding ? "TRUE" : "FALSE" DBG_PR;

      DBG_PL(ProcessGapAckBlocks, "--> rtx list chunk begin") DBG_PR;

      DBG_PL(ProcessGapAckBlocks, "    TSN=%d"),
        spCurrNodeData->spChunk->uiTsn
        DBG_PR;

      DBG_PL(ProcessGapAckBlocks, "    %s=%s %s=%s"),
        "eGapAcked",
        spCurrNodeData->eGapAcked ? "TRUE" : "FALSE",
        "eAddedToPartialBytesAcked",
        spCurrNodeData->eAddedToPartialBytesAcked ? "TRUE" : "FALSE"
        DBG_PR;

      DBG_PL(ProcessGapAckBlocks, "    NumMissingReports=%d NumTxs=%d"),
        spCurrNodeData->iNumMissingReports,
        spCurrNodeData->iNumTxs
        DBG_PR;

      DBG_PL(ProcessGapAckBlocks, "<-- rtx list chunk end") DBG_PR;
     
      DBG_PL(ProcessGapAckBlocks,"GapAckBlock StartOffset=%d EndOffset=%d"),
        spCurrGapAck->usStartOffset, spCurrGapAck->usEndOffset DBG_PR;

      uiStartTsn = spSackChunk->uiCumAck + spCurrGapAck->usStartOffset;
      uiEndTsn = spSackChunk->uiCumAck + spCurrGapAck->usEndOffset;
     
      DBG_PL(ProcessGapAckBlocks, "GapAckBlock StartTsn=%d EndTsn=%d"),
        uiStartTsn, uiEndTsn DBG_PR;

      if(spCurrNodeData->spChunk->uiTsn < uiStartTsn)
        {
          // This chunk is NOT being acked and is missing at the receiver
          //

          // If this chunk was GapAcked before, then either the
          // receiver has renegged the chunk (which our simulation
          // doesn't do) or this SACK is arriving out of order.
          //
          if(spCurrNodeData->eGapAcked == TRUE)
        {
          DBG_PL(ProcessGapAckBlocks,
            "out of order SACK? setting TSN=%d eGapAcked=FALSE"),
            spCurrNodeData->spChunk->uiTsn DBG_PR;
          spCurrNodeData->eGapAcked = FALSE;
          spCurrNodeData->spDest->iOutstandingBytes
            += spCurrNodeData->spChunk->sHdr.usLength;

          // section 6.3.2.R4 says that we should restart the
          // T3-rtx timer here if it isn't running already. In our
          // implementation, it isn't necessary since
          // ProcessSackChunk will restart the timer for any
          // destinations which have outstanding data and don't
          // have a timer running.
          //
        }
        }
      else if((uiStartTsn <= spCurrNodeData->spChunk->uiTsn) &&
          (spCurrNodeData->spChunk->uiTsn <= uiEndTsn) )
        {
          // This chunk is being acked via a gap ack block
          //
          DBG_PL(ProcessGapAckBlocks, "gap ack acks this chunk: %s%s"),
        "eGapAcked=",
        spCurrNodeData->eGapAcked ? "TRUE" : "FALSE"
        DBG_PR;

          if(spCurrNodeData->eGapAcked == FALSE)
        {
          DBG_PL(ProcessGapAckBlocks, "setting eGapAcked=TRUE") DBG_PR;
          spCurrNodeData->eGapAcked = TRUE;
          spCurrNodeData->eMarkedForRtx = FALSE; // unmark

          // modified fast rtx algorithm (implementor's guide v.02)
          //
          if(uiHighestTsnNewlySacked < spCurrNodeData->spChunk->uiTsn)
            uiHighestTsnNewlySacked = spCurrNodeData->spChunk->uiTsn;

          if(spCurrNodeData->eAdvancedAcked == FALSE)
            {
              spCurrNodeData->spDest->iNumNewlyAckedBytes
            += spCurrNodeData->spChunk->sHdr.usLength;
            }

          // only increment partial bytes acked if we are in
          // congestion avoidance mode, we have a new cum ack, and
          // we haven't already incremented it for this sack
          //
          if(( spCurrNodeData->spDest->iCwnd
              > spCurrNodeData->spDest->iSsthresh) &&
            eNewCumAck == TRUE &&
            spCurrNodeData->eAddedToPartialBytesAcked == FALSE)
            {
              DBG_PL(ProcessGapAckBlocks,
                "setting eAddedToPartiallyBytesAcked=TRUE") DBG_PR;

              spCurrNodeData->eAddedToPartialBytesAcked = TRUE; // set

              spCurrNodeData->spDest->iPartialBytesAcked
            += spCurrNodeData->spChunk->sHdr.usLength;
            }

          // BEGIN -- Timestamp changes to this function

          // We update the RTT estimate if the following hold true:
          //  1. Timestamp set for this chunk matches echoed timestamp
          //  2. This chunk has not been gap acked already
          //  3. This chunk has not been advanced acked
          //
          if(fInTimestampEcho == (float) spCurrNodeData->dTxTimestamp &&
            spCurrNodeData->eAdvancedAcked == FALSE)
            {
              RttUpdate(spCurrNodeData->dTxTimestamp,
                spCurrNodeData->spDest);
            }

          // END -- Timestamp changes to this function


          // section 6.3.2.R3 - Stop the timer if this is the
          // first outstanding for this destination (note: it may
          // have already been stopped if there was a new cum
          // ack). If there are still outstanding bytes on this
          // destination, we'll restart the timer later in
          // ProcessSackChunk()
          //
          if(eFirstOutstanding == TRUE
            && spCurrNodeData->spDest->eRtxTimerIsRunning == TRUE)
            StopT3RtxTimer(spCurrNodeData->spDest);
         
          iAssocErrorCount = 0;
         
          // trigger trace ONLY if it was previously NOT 0
          //
          if(spCurrNodeData->spDest->iErrorCount != 0)
            {
              spCurrNodeData->spDest->iErrorCount = 0; // clear errors
              tiErrorCount++;                      // ... and trace it!
              spCurrNodeData->spDest->eStatus = SCTP_DEST_STATUS_ACTIVE;
              if(spCurrNodeData->spDest == spPrimaryDest &&
            spNewTxDest != spPrimaryDest)
            {
              DBG_PL(ProcessGapAckBlocks,
                "primary recovered... "
                "migrating back from %p to %p"),
                spNewTxDest, spPrimaryDest DBG_PR;
              spNewTxDest = spPrimaryDest; // return to primary
            }
            }
        }
        }
      else if(spCurrNodeData->spChunk->uiTsn > uiEndTsn)
        {
          // This point in the rtx buffer is already past the tsns which are
          // being acked by this gap ack block. 
          //
          usNumGapAcksProcessed++;

          // Did we process all the gap ack blocks?
          //
          if(usNumGapAcksProcessed != spSackChunk->usNumGapAckBlocks)
        {
          DBG_PL(ProcessGapAckBlocks, "jump to next gap ack block")
            DBG_PR;

          spCurrGapAck
            = ((SctpGapAckBlock_S *)
              (ucpSackChunk + sizeof(SctpSackChunk_S)
            + (usNumGapAcksProcessed * sizeof(SctpGapAckBlock_S))));
        }

          // If this chunk was GapAcked before, then either the
          // receiver has renegged the chunk (which our simulation
          // doesn't do) or this SACK is arriving out of order.
          //
          if(spCurrNodeData->eGapAcked == TRUE)
        {
          DBG_PL(ProcessGapAckBlocks,
            "out of order SACK? setting TSN=%d eGapAcked=FALSE"),
            spCurrNodeData->spChunk->uiTsn DBG_PR;
          spCurrNodeData->eGapAcked = FALSE;
          spCurrNodeData->spDest->iOutstandingBytes
            += spCurrNodeData->spChunk->sHdr.usLength;
         
          // section 6.3.2.R4 says that we should restart the
          // T3-rtx timer here if it isn't running already. In our
          // implementation, it isn't necessary since
          // ProcessSackChunk will restart the timer for any
          // destinations which have outstanding data and don't
          // have a timer running.
          //
        }
        }
    }

      // By this time, either we have run through the entire send buffer or we
      // have run out of gap ack blocks. In the case that we have run out of gap
      // ack blocks before we finished running through the send buffer, we need
      // to mark the remaining chunks in the send buffer as eGapAcked=FALSE.
      // This final marking needs to be done, because we only trust gap ack info
      // from the last SACK. Otherwise, renegging (which we don't do) or out of
      // order SACKs would give the sender an incorrect view of the peer's rwnd.
      //
      for(; spCurrNode != NULL; spCurrNode = spCurrNode->spNext)
    {
      // This chunk is NOT being acked and is missing at the receiver
      //
      spCurrNodeData = (SctpSendBufferNode_S *) spCurrNode->vpData;

      // If this chunk was GapAcked before, then either the
      // receiver has renegged the chunk (which our simulation
      // doesn't do) or this SACK is arriving out of order.
      //
      if(spCurrNodeData->eGapAcked == TRUE)
        {
          DBG_PL(ProcessGapAckBlocks,
            "out of order SACK? setting TSN=%d eGapAcked=FALSE"),
        spCurrNodeData->spChunk->uiTsn DBG_PR;
          spCurrNodeData->eGapAcked = FALSE;
          spCurrNodeData->spDest->iOutstandingBytes
        += spCurrNodeData->spChunk->sHdr.usLength;

          // section 6.3.2.R4 says that we should restart the T3-rtx
          // timer here if it isn't running already. In our
          // implementation, it isn't necessary since ProcessSackChunk
          // will restart the timer for any destinations which have
          // outstanding data and don't have a timer running.
          //
        }
    }

      DBG_PL(ProcessGapAckBlocks, "now incrementing missing reports...") DBG_PR;
      DBG_PL(ProcessGapAckBlocks, "uiHighestTsnNewlySacked=%d"),
        uiHighestTsnNewlySacked DBG_PR;

      for(spCurrNode = sSendBuffer.spHead;
      spCurrNode != NULL;
      spCurrNode = spCurrNode->spNext)
    {
      spCurrNodeData = (SctpSendBufferNode_S *) spCurrNode->vpData;

      DBG_PL(ProcessGapAckBlocks, "TSN=%d eGapAcked=%s"),
        spCurrNodeData->spChunk->uiTsn,
        spCurrNodeData->eGapAcked ? "TRUE" : "FALSE"
        DBG_PR;

      if(spCurrNodeData->eGapAcked == FALSE)
        {
          // new fast rtx (implementor's guide v.02)
          //
          if(spCurrNodeData->spChunk->uiTsn < uiHighestTsnNewlySacked)
        {
          spCurrNodeData->iNumMissingReports++;
          DBG_PL(ProcessGapAckBlocks,
            "incrementing missing report for TSN=%d to %d"),
            spCurrNodeData->spChunk->uiTsn,
            spCurrNodeData->iNumMissingReports
            DBG_PR;

          if(spCurrNodeData->iNumMissingReports >= FAST_RTX_TRIGGER &&
            spCurrNodeData->eIneligibleForFastRtx == FALSE &&
            spCurrNodeData->eAdvancedAcked == FALSE)
            {
              MarkChunkForRtx(spCurrNodeData);
              eFastRtxNeeded = TRUE;
              spCurrNodeData->eIneligibleForFastRtx = TRUE;
              DBG_PL(ProcessGapAckBlocks,
                "setting eFastRtxNeeded = TRUE") DBG_PR;
            }
        }
        }
    }
    }

  DBG_PL(ProcessGapAckBlocks, "eFastRtxNeeded=%s"),
    eFastRtxNeeded ? "TRUE" : "FALSE" DBG_PR;
  DBG_X(ProcessGapAckBlocks);
  return eFastRtxNeeded;
}

void TezpurSctpAgent::ProcessHeartbeatAckChunk(SctpHeartbeatAckChunk_S
                    *spHeartbeatAckChunk)
{
  DBG_I(ProcessHeartbeatAckChunk);

  double dTime = 0;

  iAssocErrorCount = 0;

  /* trigger trace ONLY if it was previously NOT 0
  */
  if(spHeartbeatAckChunk->spDest->iErrorCount != 0)
    {
      spHeartbeatAckChunk->spDest->iErrorCount = 0; // clear the error count
      tiErrorCount++;                              // ...and trace it too!
      spHeartbeatAckChunk->spDest->eStatus = SCTP_DEST_STATUS_ACTIVE;
      if(spHeartbeatAckChunk->spDest == spPrimaryDest &&
    spNewTxDest != spPrimaryDest)
    {
      DBG_PL(ProcessHeartbeatAckChunk,
        "primary recovered... migrating back from %p to %p"),
        spNewTxDest, spPrimaryDest DBG_PR;
      spNewTxDest = spPrimaryDest; // return to primary
    }
    }

  RttUpdate(spHeartbeatAckChunk->dTimestamp, spHeartbeatAckChunk->spDest);

  DBG_PL(ProcessHeartbeatAckChunk, "set rto of dest=%p to %f"),
    spHeartbeatAckChunk->spDest, spHeartbeatAckChunk->spDest->dRto DBG_PR;

  if(eOneHeartbeatTimer == TRUE && uiHeartbeatInterval != 0)
    {
      opHeartbeatTimeoutTimer->force_cancel();
    }
  else if(uiHeartbeatInterval != 0)
    {
      spHeartbeatAckChunk->spDest->opHeartbeatTimeoutTimer->force_cancel();
      DBG_PL(ProcessHeartbeatAckChunk,
        "about to calculate heartbeat time for dest=%p"),
    spHeartbeatAckChunk->spDest DBG_PR;
      dTime = CalcHeartbeatTime(spHeartbeatAckChunk->spDest->dRto);
      spHeartbeatAckChunk->spDest->opHeartbeatGenTimer->resched(dTime);
    }

  DBG_X(ProcessHeartbeatAckChunk);
}


void TezpurSctpAgent::ProcessSackChunk(u_char *ucpSackChunk)
{
  DBG_I(ProcessSackChunk);

  SctpSackChunk_S *spSackChunk = (SctpSackChunk_S *) ucpSackChunk;

  DBG_PL(ProcessSackChunk, "cum=%d arwnd=%d #gapacks=%d #duptsns=%d"),
    spSackChunk->uiCumAck, spSackChunk->uiArwnd,
    spSackChunk->usNumGapAckBlocks, spSackChunk->usNumDupTsns
    DBG_PR;

  Boolean_E eFastRtxNeeded = FALSE;
  Boolean_E eNewCumAck = FALSE;
  Boolean_E eMoreMarkedChunks = TRUE;
  Node_S *spCurrDestNode = NULL;
  SctpDest_S *spCurrDestNodeData = NULL;
  u_int uiTotalOutstanding = 0;
  int i = 0;

  /* make sure we clear all the iNumNewlyAckedBytes before using them!
  */
  for(spCurrDestNode = sDestList.spHead;
      spCurrDestNode != NULL;
      spCurrDestNode = spCurrDestNode->spNext)
    {
      spCurrDestNodeData = (SctpDest_S *) spCurrDestNode->vpData;
      spCurrDestNodeData->iNumNewlyAckedBytes = 0;
      spCurrDestNodeData->eSeenFirstOutstanding = FALSE;
    }

  if(spSackChunk->uiCumAck < uiCumAckPoint)
    {
      /* this cumAck's a previously cumAck'd tsn (ie, it's out of order!)
      * ...so ignore!
      */
      DBG_PL(ProcessSackChunk, "ignoring out of order sack!") DBG_PR;
      DBG_X(ProcessSackChunk);
      return;
    }
  else if(spSackChunk->uiCumAck > uiCumAckPoint)
    {
      eNewCumAck = TRUE; // incomding SACK's cum ack advances the cum ack point
      SendBufferDequeueUpTo(spSackChunk->uiCumAck);
      uiCumAckPoint = spSackChunk->uiCumAck; // Advance the cumAck pointer
    }

  if(spSackChunk->usNumGapAckBlocks != 0) // are there any gaps??
    {
      eFastRtxNeeded = ProcessGapAckBlocks(ucpSackChunk, eNewCumAck);
    }

  for(spCurrDestNode = sDestList.spHead;
      spCurrDestNode != NULL;
      spCurrDestNode = spCurrDestNode->spNext)
    {
      spCurrDestNodeData = (SctpDest_S *) spCurrDestNode->vpData;

      /* Only adjust cwnd if sack advanced the cum ack point AND this
      * destination has newly acked bytes. Also, we MUST adjust our
      * congestion window BEFORE we update the number of outstanding
      * bytes to reflect the newly acked bytes in received SACK. 
      */
      if(eNewCumAck == TRUE && spCurrDestNodeData->iNumNewlyAckedBytes > 0)
    AdjustCwnd(spCurrDestNodeData);

      /* The number of outstanding bytes is reduced by how many bytes this sack
      * acknowledges.
      */
      if(spCurrDestNodeData->iNumNewlyAckedBytes <=
    spCurrDestNodeData->iOutstandingBytes)
    {
      spCurrDestNodeData->iOutstandingBytes
        -= spCurrDestNodeData->iNumNewlyAckedBytes;
    }
      else
    spCurrDestNodeData->iOutstandingBytes = 0;

      DBG_PL(ProcessSackChunk,"Dest #%d (%d:%d) (%p): outstanding=%d, cwnd=%d"),
    ++i, spCurrDestNodeData->iNsAddr, spCurrDestNodeData->iNsPort,
    spCurrDestNodeData, spCurrDestNodeData->iOutstandingBytes,
    spCurrDestNodeData->iCwnd DBG_PR;

      if(spCurrDestNodeData->iOutstandingBytes == 0)
    {
      /* All outstanding data has been acked
      */
      spCurrDestNodeData->iPartialBytesAcked = 0;  // section 7.2.2

      /* section 6.3.2.R2
      */
      if(spCurrDestNodeData->eRtxTimerIsRunning == TRUE)
        {
          DBG_PL(ProcessSackChunk, "Dest #%d (%p): stopping timer"),
        i, spCurrDestNodeData DBG_PR;
          StopT3RtxTimer(spCurrDestNodeData);
        }
    }

      /* section 6.3.2.R3 - Restart timers for destinations that have
      * acknowledged their first outstanding (ie, no timer running) and
      * still have outstanding data in flight. 
      */
      if(spCurrDestNodeData->iOutstandingBytes > 0 &&
    spCurrDestNodeData->eRtxTimerIsRunning == FALSE)
    {
      StartT3RtxTimer(spCurrDestNodeData);
    }
    }

  DBG_F(ProcessSackChunk, DumpSendBuffer());

  AdvancePeerAckPoint();

  if(eFastRtxNeeded == TRUE)  // section 7.2.4
    FastRtx();

  /* Let's see if after process this sack, there are still any chunks
  * pending... If so, rtx all allowed by cwnd.
  */
  else if( (eMarkedChunksPending = AnyMarkedChunks()) == TRUE)
    {
      /* section 6.1.C) When the time comes for the sender to
      * transmit, before sending new DATA chunks, the sender MUST
      * first transmit any outstanding DATA chunks which are marked
      * for retransmission (limited by the current cwnd). 
      */
      RtxMarkedChunks(RTX_LIMIT_CWND);
    }

  /* (6.2.1.D.ii) Adjust PeerRwnd based on total oustanding bytes on all
  * destinations. We need to this adjustment after any
  * retransmissions. Otherwise the sender's view of the peer rwnd will be
  * off, because the number outstanding increases again once a marked
  * chunk gets retransmitted (when marked, outstanding is decreased).
  */
  uiTotalOutstanding = TotalOutstanding();
  if(uiTotalOutstanding <= spSackChunk->uiArwnd)
    uiPeerRwnd = (spSackChunk->uiArwnd  - uiTotalOutstanding);
  else
    uiPeerRwnd = 0;
 
  DBG_PL(ProcessSackChunk, "uiPeerRwnd=%d, uiArwnd=%d"), uiPeerRwnd,
    spSackChunk->uiArwnd DBG_PR;
  DBG_X(ProcessSackChunk);
}


int TezpurSctpAgent::ProcessChunk(u_char *ucpInChunk, u_char **ucppOutData)
{
  DBG_I(ProcessChunk);
  int iThisOutDataSize = 0;
  Node_S *spCurrNode = NULL;
  SctpDest_S *spCurrDest = NULL;
  double dCurrTime = Scheduler::instance().clock();
  double dTime;
  SctpHeartbeatAckChunk_S *spHeartbeatChunk = NULL;
  SctpHeartbeatAckChunk_S *spHeartbeatAckChunk = NULL;

  switch(eState)
    {
    case SCTP_STATE_CLOSED:
      switch( ((SctpChunkHdr_S *)ucpInChunk)->ucType)
    {
    case SCTP_CHUNK_INIT:
      DBG_PL(ProcessChunk, "got INIT!! ...sending INIT_ACK") DBG_PR;
      ProcessInitChunk(ucpInChunk);
      iThisOutDataSize = GenChunk(SCTP_CHUNK_INIT_ACK, *ucppOutData);
      *ucppOutData += iThisOutDataSize;
      /* stay in the closed state */
      break;

    case SCTP_CHUNK_COOKIE_ECHO:
      DBG_PL(ProcessChunk,
        "got COOKIE_ECHO!! (established!) ...sending COOKIE_ACK")
        DBG_PR;
      ProcessCookieEchoChunk( (SctpCookieEchoChunk_S *) ucpInChunk );
      iThisOutDataSize = GenChunk(SCTP_CHUNK_COOKIE_ACK, *ucppOutData);
      *ucppOutData += iThisOutDataSize;
      eState = SCTP_STATE_ESTABLISHED;
      if(eOneHeartbeatTimer == TRUE && uiHeartbeatInterval != 0)
        {
          dTime = CalcHeartbeatTime(spPrimaryDest->dRto);
          opHeartbeatGenTimer->force_cancel();
          opHeartbeatGenTimer->resched(dTime);
          opHeartbeatGenTimer->dStartTime = dCurrTime;

          for(spCurrNode = sDestList.spHead;
          spCurrNode != NULL;
          spCurrNode = spCurrNode->spNext)
        {
          spCurrDest = (SctpDest_S *) spCurrNode->vpData;
          spCurrDest->dIdleSince = dCurrTime;
        }
        }
      else if(uiHeartbeatInterval != 0)
        {
          for(spCurrNode = sDestList.spHead;
          spCurrNode != NULL;
          spCurrNode = spCurrNode->spNext)
        {
          spCurrDest = (SctpDest_S *) spCurrNode->vpData;
          DBG_PL(Reset, "about to calculate HB time for dest=%p"),
            spCurrDest DBG_PR;
          dTime = CalcHeartbeatTime(spCurrDest->dRto);
          spCurrDest->opHeartbeatGenTimer->resched(dTime);
        }
        }
      break;
     
      default:
      /* ALC 1/25/2002
      *
      * no error statement here, because there are times when this could
      * occur due to abrupt disconnections via the "reset" command. how?
      * well, "reset" resets all the association state. however, there may
      * still be packets in transit. if and when those packets arrive, they
      * will be unexpected packets since the association is closed. since
      * this is a simulation, it shouldn't be a problem. however, if an
      * application needs a more graceful shutdown, we would need to
      * implement sctp's proper shutdown procedure. until the need arises,
      * we won't do it. instead, what do we do? ignore the "unexpected"
      * packet.
      */
      DBG_PL(ProcessChunk, "association closed... ignoring chunk %s"),
        "(not COOKIE_ECHO or INIT)" DBG_PR;
      break;
    }
      break;
     
    case SCTP_STATE_COOKIE_WAIT:
      DBG_PL(ProcessChunk, "got INIT_ACK!! ...sending COOKIE_ECHO") DBG_PR;
      ProcessInitAckChunk(ucpInChunk);
      iThisOutDataSize = GenChunk(SCTP_CHUNK_COOKIE_ECHO, *ucppOutData);
      *ucppOutData += iThisOutDataSize;
      opT1CookieTimer->resched(spPrimaryDest->dRto);
      eState = SCTP_STATE_COOKIE_ECHOED;
      break;

    case SCTP_STATE_COOKIE_ECHOED:
      DBG_PL(ProcessChunk, "got COOKIE_ACK!! (established!) ...sending DATA")
    DBG_PR;
      ProcessCookieAckChunk( (SctpCookieAckChunk_S *) ucpInChunk );
      eSendNewDataChunks = TRUE;
      eState = SCTP_STATE_ESTABLISHED;
      if(eOneHeartbeatTimer == TRUE && uiHeartbeatInterval != 0)
    {
      dTime = CalcHeartbeatTime(spPrimaryDest->dRto);
      opHeartbeatGenTimer->force_cancel();
      opHeartbeatGenTimer->resched(dTime);
      opHeartbeatGenTimer->dStartTime = dCurrTime;

      for(spCurrNode = sDestList.spHead;
          spCurrNode != NULL;
          spCurrNode = spCurrNode->spNext)
        {
          spCurrDest = (SctpDest_S *) spCurrNode->vpData;
          spCurrDest->dIdleSince = dCurrTime;
        }
    }
      else if(uiHeartbeatInterval != 0)
    {
      for(spCurrNode = sDestList.spHead;
          spCurrNode != NULL;
          spCurrNode = spCurrNode->spNext)
        {
          spCurrDest = (SctpDest_S *) spCurrNode->vpData;
          DBG_PL(Reset, "about to calculate HB time for dest=%p"),
        spCurrDest DBG_PR;
          dTime = CalcHeartbeatTime(spCurrDest->dRto);
          spCurrDest->opHeartbeatGenTimer->resched(dTime);
        }
    }
      break;

    case SCTP_STATE_ESTABLISHED:
      switch( ((SctpChunkHdr_S *)ucpInChunk)->ucType)
    {
    case SCTP_CHUNK_DATA:
      DBG_PL(ProcessChunk, "got DATA (TSN=%d)!!"),
        ((SctpDataChunkHdr_S *)ucpInChunk)->uiTsn DBG_PR;

      if(eUseDelayedSacks == FALSE) // are we doing delayed sacks?
        {
          /* NO, so generate sack immediately!
          */
          eSackChunkNeeded = TRUE;
        }
      else  // we are doing delayed sacks, so...
        {
          /* rfc2960 section 6.2 - determine if a SACK will be generated
          */
          if(eStartOfPacket == TRUE) 
        {
          eStartOfPacket = FALSE;  // reset
          iDataPktCountSinceLastSack++;

          if(iDataPktCountSinceLastSack == 1) 
            {
              opSackGenTimer->resched(SACK_GEN_TIMEOUT);
            }
          else if(iDataPktCountSinceLastSack == DELAYED_SACK_TRIGGER)
            {
              iDataPktCountSinceLastSack = 0; // reset
              opSackGenTimer->force_cancel();
              eSackChunkNeeded = TRUE;
            }
        }
        }

      ProcessDataChunk( (SctpDataChunkHdr_S *) ucpInChunk );

      /* section 6.7 - There is at least one "gap in the received DATA
      * chunk sequence", so let's ensure we send a SACK immediately!
      */
      if(sRecvTsnBlockList.uiLength > 0)
        {
          iDataPktCountSinceLastSack = 0; // reset
          opSackGenTimer->force_cancel();
          eSackChunkNeeded = TRUE;
        }

      /* no state change
      */     
      break;

    case SCTP_CHUNK_SACK:
      DBG_PL(ProcessChunk, "got SACK (CumAck=%d)!!"),
        ((SctpSackChunk_S *)ucpInChunk)->uiCumAck DBG_PR;

      ProcessSackChunk(ucpInChunk);

      /* Do we need to transmit a FORWARD TSN chunk??
      */
      if(uiAdvancedPeerAckPoint > uiCumAckPoint)
        eForwardTsnNeeded = TRUE;

      eSendNewDataChunks = TRUE;
      break; // no state change

    case SCTP_CHUNK_FORWARD_TSN:
      DBG_PL(ProcessChunk, "got FORWARD TSN (tsn=%d)!!"),
        ((SctpForwardTsnChunk_S *) ucpInChunk)->uiNewCum DBG_PR;

      ProcessForwardTsnChunk( (SctpForwardTsnChunk_S *) ucpInChunk );
      break; // no state change

    case SCTP_CHUNK_HB:
      DBG_PL(ProcessChunk, "got HEARTBEAT!!") DBG_PR;

      /* GenChunk() doesn't copy HB info
      */
      iThisOutDataSize = GenChunk(SCTP_CHUNK_HB_ACK, *ucppOutData);

      /* ...so we copy it here!
      */
      spHeartbeatChunk = (SctpHeartbeatAckChunk_S *) ucpInChunk;
      spHeartbeatAckChunk = (SctpHeartbeatAckChunk_S *) *ucppOutData;
      spHeartbeatAckChunk->dTimestamp = spHeartbeatChunk->dTimestamp;
      spHeartbeatAckChunk->spDest = spHeartbeatChunk->spDest;
      *ucppOutData += iThisOutDataSize;
      break; // no state change

    case SCTP_CHUNK_HB_ACK:
      DBG_PL(ProcessChunk, "got HEARTBEAT ACK!!") DBG_PR;
      ProcessHeartbeatAckChunk( (SctpHeartbeatAckChunk_S *) ucpInChunk);
      break; // no state change

    case SCTP_CHUNK_INIT:
      DBG_PL(ProcessChunk, "unexpected chunk type (INIT) at %f"),
        dCurrTime DBG_PR;
      printf("[ProcessChunk] unexpected chunk type (INIT) at %f\n",
        dCurrTime);
      break;

    case SCTP_CHUNK_INIT_ACK:
      DBG_PL(ProcessChunk, "unexpected chunk type (INIT_ACK) at %f"),
        dCurrTime DBG_PR;
      printf("[ProcessChunk] unexpected chunk type (INIT_ACK) at %f\n",
        dCurrTime);
      break;

      /* even though the association is established, COOKIE_ECHO needs to be
      * handled because the peer may have not received the COOKIE_ACK.
      *
      * Note: we don't follow the rfc's complex process for handling this
      * case, because we don't deal with tie-tags, etc in simulation. :-)
      */
    case SCTP_CHUNK_COOKIE_ECHO:
      DBG_PL(ProcessChunk,
        "got COOKIE_ECHO!! (established!) ...sending COOKIE_ACK")
        DBG_PR;
      ProcessCookieEchoChunk( (SctpCookieEchoChunk_S *) ucpInChunk);
      iThisOutDataSize = GenChunk(SCTP_CHUNK_COOKIE_ACK, *ucppOutData);
      *ucppOutData += iThisOutDataSize;
      break;

    case SCTP_CHUNK_COOKIE_ACK:
      DBG_PL(ProcessChunk, "unexpected chunk type (COOKIE_ACK) at %f"),
        dCurrTime DBG_PR;
      printf("[ProcessChunk] unexpected chunk type (COOKIE_ACK) at %f\n",
        dCurrTime);
      break;

    default:
      ProcessOptionChunk(ucpInChunk);
      break;
    }
      break;
    } 

  DBG_X(ProcessChunk);
  return iThisOutDataSize;
}
/*Check Status of the Path to the Current Primary Destination; 20/08/2005
* If Present Primary is not good then set the alternate one (or another good one) as Primary
*/
void TezpurSctpAgent::CheckPathStat()
{

    if(spPrimaryDest->tzCB.tz_crtt_ > spPrimaryDest->tzCB.tz_rtt_thresh_ &&
        //spPrimaryDest->tzCB.tz_crtt_ > spPrimaryDest->tzCB.tz_prtt_  && spPrimaryDest->tzCB.tz_prtt_>0)
        spPrimaryDest->tzCB.tz_crtt_ > spPrimaryDest->tzCB.tz_prtt_  &&
            spPrimaryDest->tzCB.tz_prtt_ > spPrimaryDest->tzCB.tz_pprtt_ && spPrimaryDest->tzCB.tz_pprtt_>0)
            //Above on 23/08/2005
        {
       
          Node_S *spCurrNode=NULL;
          SctpDest_S *spCurrDest=NULL;
   
          for(spCurrNode = sDestList.spHead; spCurrNode != NULL; spCurrNode = spCurrNode->spNext)
            {
                spCurrDest = (SctpDest_S *) spCurrNode->vpData;
            if (spPrimaryDest->iNsAddr != spCurrDest->iNsAddr)
                          {
                SetPrimary(spCurrDest->iNsAddr);
                spPrimaryDest->iCwnd = max(spPrimaryDest->iCwnd/2,2*uiMaxDataSize);    
                break;
                          }
            }

    }

             
} 


