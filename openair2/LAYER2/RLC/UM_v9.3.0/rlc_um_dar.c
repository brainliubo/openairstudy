/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#define RLC_UM_MODULE 1
#define RLC_UM_DAR_C 1
#include "platform_types.h"
#include "assertions.h"
//-----------------------------------------------------------------------------
#include "msc.h"
#include "rlc.h"
#include "rlc_um.h"
#include "rlc_primitives.h"
#include "mac_primitives.h"
#include "list.h"
#include "common/utils/LOG/log.h"
#include "common/utils/LOG/vcd_signal_dumper.h"
//-----------------------------------------------------------------------------
signed int rlc_um_get_pdu_infos(
  const protocol_ctxt_t* const ctxt_pP,
  const rlc_um_entity_t* const rlc_pP,
  rlc_um_pdu_sn_10_t   * const header_pP,
  const sdu_size_t             total_sizeP,
  rlc_um_pdu_info_t    * const pdu_info_pP,
  const uint8_t                sn_lengthP)
{
  sdu_size_t         sum_li = 0;
  memset(pdu_info_pP, 0, sizeof (rlc_um_pdu_info_t));

  pdu_info_pP->num_li = 0;

  //AssertFatal( total_sizeP > 0 , "RLC UM PDU LENGTH %d", total_sizeP);
  if(total_sizeP <= 0) {
    LOG_E(RLC, "RLC UM PDU LENGTH %d\n", total_sizeP);
    return -1;
  }
　//! header中解析出来PDU 的info
  if (sn_lengthP == 10) {
    pdu_info_pP->fi           = (header_pP->b1 >> 3) & 0x03;
    pdu_info_pP->e            = (header_pP->b1 >> 2) & 0x01;
    pdu_info_pP->sn           = header_pP->b2 + (((uint16_t)(header_pP->b1 & 0x03)) << 8);
    pdu_info_pP->header_size  = 2;
    pdu_info_pP->payload      = &header_pP->data[0];
  } else if (sn_lengthP == 5) {
    pdu_info_pP->fi           = (header_pP->b1 >> 6) & 0x03;
    pdu_info_pP->e            = (header_pP->b1 >> 5) & 0x01;
    pdu_info_pP->sn           = header_pP->b1 & 0x1F;
    pdu_info_pP->header_size  = 1;
    pdu_info_pP->payload      = &header_pP->b2;
  } else {
    //AssertFatal( sn_lengthP == 5 || sn_lengthP == 10, "RLC UM SN LENGTH %d", sn_lengthP);
    if(!(sn_lengthP == 5 || sn_lengthP == 10)) {
      LOG_E(RLC, "RLC UM SN LENGTH %d\n", sn_lengthP);
      return -1;
    }
  }


  if (pdu_info_pP->e) {  //E表示后面还有E+LI
    rlc_am_e_li_t      *e_li_p;
    unsigned int li_length_in_bytes  = 1;
    unsigned int li_to_read          = 1;

    e_li_p = (rlc_am_e_li_t*)(pdu_info_pP->payload); 

    while (li_to_read)  {
      li_length_in_bytes = li_length_in_bytes ^ 3; //！= 2

        //！这里的读取分成2种，先读2byte，然后再看情况是否有后面的LI 需要读取
      if (li_length_in_bytes  == 2) { //！偶数个LI ，占2个byte 
        //AssertFatal( total_sizeP >= ((uint64_t)(&e_li_p->b2) - (uint64_t)header_pP),
        //             "DECODING PDU TOO FAR PDU size %d", total_sizeP);
        if(total_sizeP < ((uint64_t)(&e_li_p->b2) - (uint64_t)header_pP)) {
          LOG_E(RLC, "DECODING PDU TOO FAR PDU size %d\n", total_sizeP);
          return -1;
        }

		//将LI 从b1,b2中提出来，b2中包含了4bit的padding ,b1中包含了E的值 
        pdu_info_pP->li_list[pdu_info_pP->num_li] = ((uint16_t)(e_li_p->b1 << 4)) & 0x07F0;
        pdu_info_pP->li_list[pdu_info_pP->num_li] |= (((uint8_t)(e_li_p->b2 >> 4)) & 0x000F);
        li_to_read = e_li_p->b1 & 0x80; //是否还需要继续读LI 
        pdu_info_pP->header_size  += 2;
      } else { //!如果还有下一个E+LI,则从b2开始读取
        //AssertFatal( total_sizeP >= ((uint64_t)(&e_li_p->b3) - (uint64_t)header_pP),
        //             "DECODING PDU TOO FAR PDU size %d", total_sizeP);
        if(total_sizeP < ((uint64_t)(&e_li_p->b3) - (uint64_t)header_pP)) {
          LOG_E(RLC, "DECODING PDU TOO FAR PDU size %d\n", total_sizeP);
          return -1;
        }
		//取b2的低3bit, 并且右移8bit,和b3或，得到LI+E
        pdu_info_pP->li_list[pdu_info_pP->num_li] = ((uint16_t)(e_li_p->b2 << 8)) & 0x0700;
        pdu_info_pP->li_list[pdu_info_pP->num_li] |=  e_li_p->b3;
        li_to_read = e_li_p->b2 & 0x08;
        e_li_p++;
        pdu_info_pP->header_size  += 1;
      }

      //AssertFatal( pdu_info_pP->num_li <= RLC_UM_SEGMENT_NB_MAX_LI_PER_PDU,
      //             PROTOCOL_RLC_UM_CTXT_FMT"[GET PDU INFO]  SN %04d TOO MANY LIs ",
      //             PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
      //             pdu_info_pP->sn);
      if(pdu_info_pP->num_li > RLC_UM_SEGMENT_NB_MAX_LI_PER_PDU) {
        LOG_E(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[GET PDU INFO]  SN %04d TOO MANY LIs \n",
                   PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                   pdu_info_pP->sn);
        return -1;
      }

      sum_li += pdu_info_pP->li_list[pdu_info_pP->num_li]; //每一个segment 的Length相加 
      pdu_info_pP->num_li = pdu_info_pP->num_li + 1; //最后一个segment没有LI 

      if (pdu_info_pP->num_li > RLC_UM_SEGMENT_NB_MAX_LI_PER_PDU) {
        return -2;
      }
    }

    if (li_length_in_bytes  == 2) {
      pdu_info_pP->payload = &e_li_p->b3; //表示最后一次是只占2个byte的LI,data 从b3开始 
    } else {
      pdu_info_pP->payload = &e_li_p->b1; //!表示最后一次是占3个byte的LI,所以data 从b1开始
    }
  }
  //减去header就是data field的size 
  pdu_info_pP->payload_size = total_sizeP - pdu_info_pP->header_size;
   //data field size > LI之和，则说明data filed中还有hidden size 
  if (pdu_info_pP->payload_size > sum_li) {
    pdu_info_pP->hidden_size = pdu_info_pP->payload_size - sum_li;
  }

  return 0;
}
//-----------------------------------------------------------------------------
//！读取扩展部分的E+LI

int rlc_um_read_length_indicators(unsigned char**data_ppP, rlc_um_e_li_t* e_liP, unsigned int* li_array_pP, unsigned int *num_li_pP, sdu_size_t *data_size_pP)
{
  int          continue_loop = 1;
  unsigned int e1  = 0;
  unsigned int li1 = 0;
  unsigned int e2  = 0;
  unsigned int li2 = 0;
  *num_li_pP = 0;

  while ((continue_loop)) {
    //msg("[RLC_UM] e_liP->b1 = %02X\n", e_liP->b1);
    //msg("[RLC_UM] e_liP->b2 = %02X\n", e_liP->b2);

	//!1bit的E,11bit的LI 
    e1 = ((unsigned int)e_liP->b1 & 0x00000080) >> 7;
    li1 = (((unsigned int)e_liP->b1 & 0x0000007F) << 4) + (((unsigned int)e_liP->b2 & 0x000000F0) >> 4);
    li_array_pP[*num_li_pP] = li1; //！第一个data segment 的长度 
    *data_size_pP = *data_size_pP - li1 - 2;  //！减去第一个data segment ，还要减去2，是减去E+LI的字节数 
    *num_li_pP = *num_li_pP +1;

    if ((e1)) { //！如果E1表示后面还有一个E+LI
      e2 = ((unsigned int)e_liP->b2 & 0x00000008) >> 3; //!第二个E
      li2 = (((unsigned int)e_liP->b2 & 0x00000007) << 8) + ((unsigned int)e_liP->b3 & 0x000000FF);
      li_array_pP[*num_li_pP] = li2;
      *data_size_pP = *data_size_pP - li2 - 1; //!这里再减去1byte,这样当有2个E+LI时，减去的就是3个BYTE 
      *num_li_pP = *num_li_pP +1;

      if (!(*data_size_pP >= 0)) LOG_E(RLC, "Invalid data_size=%d! (pdu_size=%d loop=%d e1=%d e2=%d li2=%d e_liP=%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x)\n",
          *data_size_pP, *data_size_pP, continue_loop, e1, e2, li2,
          (e_liP-(continue_loop-1)+0)->b1,
          (e_liP-(continue_loop-1)+0)->b2,
          (e_liP-(continue_loop-1)+0)->b3,
          (e_liP-(continue_loop-1)+1)->b1,
          (e_liP-(continue_loop-1)+1)->b2,
          (e_liP-(continue_loop-1)+1)->b3,
          (e_liP-(continue_loop-1)+2)->b1,
          (e_liP-(continue_loop-1)+2)->b2,
          (e_liP-(continue_loop-1)+2)->b3);
      // AssertFatal(*data_size_pP >= 0, "Invalid data_size!");

      if (e2 == 0) {
        continue_loop = 0;  //!后面没有扩展部分了，停止读取LI
      } else {  //!如果e2后面还有，则继续
        e_liP++;
        continue_loop++;
      }
    } else {
      //如果E1后面没有扩展部分了，那么后面就是数据了 
      if (!(*data_size_pP >= 0)) LOG_E(RLC, "Invalid data_size=%d! (pdu_size=%d loop=%d e1=%d li1=%d e_liP=%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x.%02x)\n",
          *data_size_pP, *data_size_pP, continue_loop, e1, li1,
          (e_liP-(continue_loop-1)+0)->b1,
          (e_liP-(continue_loop-1)+0)->b2,
          (e_liP-(continue_loop-1)+0)->b3,
          (e_liP-(continue_loop-1)+1)->b1,
          (e_liP-(continue_loop-1)+1)->b2,
          (e_liP-(continue_loop-1)+1)->b3,
          (e_liP-(continue_loop-1)+2)->b1,
          (e_liP-(continue_loop-1)+2)->b2,
          (e_liP-(continue_loop-1)+2)->b3);
      continue_loop = 0;
      // AssertFatal(*data_size_pP >= 0, "Invalid data_size!");
    }

    if (*num_li_pP > RLC_UM_SEGMENT_NB_MAX_LI_PER_PDU) {
      return -1;
    }
  }

  *data_ppP = *data_ppP + (((*num_li_pP*3) +1) >> 1); //!偏移掉LI,来到data field
  if (*data_size_pP > 0) {
    return 0;
  } else if (*data_size_pP == 0) { //！最后没有数据了
    LOG_W(RLC, "Last RLC SDU size is zero!\n");
    return -1;
  } else {
    LOG_W(RLC, "Last RLC SDU size is negative %d!\n", *data_size_pP);
    return -1;
  }
}
//-----------------------------------------------------------------------------
//!将满足接收条件，并且不在recording窗内的PDU 进行去掉Header，
//!并重新组装，按照SN 的顺序发给上层

void
rlc_um_try_reassembly(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t *            rlc_pP,
  rlc_sn_t                     start_snP,
  rlc_sn_t                     end_snP)
{
  mem_block_t        *pdu_mem_p              = NULL;
  struct mac_tb_ind  *tb_ind_p               = NULL;
  rlc_um_e_li_t      *e_li_p                 = NULL;
  unsigned char      *data_p                 = NULL;
  int                 e                      = 0;
  int                 fi                     = 0;
  sdu_size_t          size                   = 0;
  rlc_sn_t            sn                     = 0;
  unsigned int        continue_reassembly    = 0;
  unsigned int        num_li                 = 0;
  unsigned int        li_array[RLC_UM_SEGMENT_NB_MAX_LI_PER_PDU];
  int                 i                      = 0;
  int                 reassembly_start_index = 0;

  VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_TRY_REASSEMBLY,VCD_FUNCTION_IN);

  if (end_snP < 0)   {
    end_snP   = end_snP   + rlc_pP->rx_sn_modulo;
  }

  if (start_snP < 0) {
    start_snP = start_snP + rlc_pP->rx_sn_modulo;
  }

#if TRACE_RLC_UM_DAR
  LOG_D(RLC,  PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY FROM PDU SN=%03d+1  TO  PDU SN=%03d   SN Length = %d bits (%s:%u)\n",
        PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
        rlc_pP->last_reassemblied_sn,
        end_snP,
        rlc_pP->rx_sn_length,
        __FILE__,
        __LINE__);
#endif

  // nothing to be reassemblied
  if (start_snP == end_snP) {
    VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_TRY_REASSEMBLY,VCD_FUNCTION_OUT);
    return;
  }

  continue_reassembly = 1;
  //sn = (rlc_pP->last_reassemblied_sn + 1) % rlc_pP->rx_sn_modulo;
  sn = start_snP;

  //check_mem_area();

  while (continue_reassembly) {
  	//!之前已经把数据存放在dar_buffer中了，按照SN的顺序
    if ((pdu_mem_p = rlc_pP->dar_buffer[sn])) {
       //如果SN 不等于之前最后一次组包的SN+1,那么说明有PDU 丢失
      if ((rlc_pP->last_reassemblied_sn+1)%rlc_pP->rx_sn_modulo != sn) {
#if TRACE_RLC_UM_DAR
        LOG_W(RLC,
              PROTOCOL_RLC_UM_CTXT_FMT" FINDING a HOLE in RLC UM SN: CLEARING OUTPUT SDU BECAUSE NEW SN (%03d) TO REASSEMBLY NOT CONTIGUOUS WITH LAST REASSEMBLIED SN (%03d) (%s:%u)\n",
              PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
              sn,
              rlc_pP->last_reassemblied_sn,
              __FILE__,
              __LINE__);
#endif
        //！将 output_sdu_size_to_write 设置为0 
        rlc_um_clear_rx_sdu(ctxt_pP, rlc_pP);
      }

      rlc_pP->last_reassemblied_sn = sn;  //!更新最新的组包SN号
      tb_ind_p = (struct mac_tb_ind *)(pdu_mem_p->data);
	  
       //!按照SN = 10进行处理，得到e和FI,以及扩展部分的E+LI的部分 
      if (rlc_pP->rx_sn_length == 10) {
#if TRACE_RLC_UM_DAR
        LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY 10 PDU SN=%03d\n (%s:%u)",
              PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
              sn,
              __FILE__,
              __LINE__);
#endif
    
        e  = (((rlc_um_pdu_sn_10_t*)(tb_ind_p->data_ptr))->b1 & 0x04) >> 2; //bit2
        fi = (((rlc_um_pdu_sn_10_t*)(tb_ind_p->data_ptr))->b1 & 0x18) >> 3; //bit3,bit4 
        
        e_li_p = (rlc_um_e_li_t*)((rlc_um_pdu_sn_10_t*)(tb_ind_p->data_ptr))->data; //!指向E_LI的首地址地址
        size   = tb_ind_p->size - 2; //！减去固定header 
        data_p = &tb_ind_p->data_ptr[2]; //!指向固定header之后的地址
      } else {  //！SN = 5的代码不用看
#if TRACE_RLC_UM_DAR
        LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY 5 PDU SN=%03d Byte 0=%02X (%s:%u)\n",
              PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
              sn,
              ((rlc_um_pdu_sn_5_t*)(tb_ind_p->data_ptr))->b1,
              __FILE__,
              __LINE__);
#endif
        e  = (((rlc_um_pdu_sn_5_t*)(tb_ind_p->data_ptr))->b1 & 0x00000020) >> 5;
        fi = (((rlc_um_pdu_sn_5_t*)(tb_ind_p->data_ptr))->b1 & 0x000000C0) >> 6;
        e_li_p = (rlc_um_e_li_t*)((rlc_um_pdu_sn_5_t*)(tb_ind_p->data_ptr))->data;
        size   = tb_ind_p->size - 1;
        data_p = &tb_ind_p->data_ptr[1];
#if TRACE_RLC_UM_DAR
        LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" e=%01X fi=%01X\n",
              PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
              e,
              fi,
              __FILE__,
              __LINE__);
#endif
      }
      //AssertFatal(size >= 0, "invalid size!");
      //AssertFatal((e==0) || (e==1), "invalid e!");
      //AssertFatal((fi >= 0) && (fi <= 3), "invalid fi!");
      //!如果当前的SN 的PDU 中的header参数异常，或者size 不对，则sn +1,处理下一个sn 
      if((size < 0) || ((e!=0) && (e!=1)) || ((fi < 0) || (fi > 3))){
        LOG_E(RLC, "invalid size %d, e %d, fi %d\n", size, e, fi);
        sn = (sn + 1) % rlc_pP->rx_sn_modulo;
        if ((sn == rlc_pP->vr_uh) || (sn == end_snP)) {
          continue_reassembly = 0;
        }
        continue;
      }

	  //!如果header之后是data field 
      if (e == RLC_E_FIXED_PART_DATA_FIELD_FOLLOW) {
        switch (fi) {
		//!bit[1]表示fist byte， 0表示是，1表示不是
		//!bit[0]表示last byte,  0表示是，1表示不是 
		
        case RLC_FI_1ST_BYTE_DATA_IS_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
          LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU NO E_LI FI=11 (00) (%s:%u)\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                __FILE__,
                __LINE__);
#endif
          // one complete SDU
          //LGrlc_um_send_sdu(rlc_pP,ctxt_pP->frame,ctxt_pP->enb_flag); // may be not necessary
          //! 这包PDU中的数据中，PDU是整个的SDU 
          rlc_um_clear_rx_sdu(ctxt_pP, rlc_pP);
          //！这里由于没有扩展部分，因此data_p 指向的就是data field 
          //! 将data_p的数据往SDU 的接收buffer中放
          rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size);
		  
          rlc_um_send_sdu(ctxt_pP, rlc_pP); //!将当前SDU中的数据发送给PDCP 
          rlc_pP->reassembly_missing_sn_detected = 0;

          break;

        case RLC_FI_1ST_BYTE_DATA_IS_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_NOT_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
          LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU NO E_LI FI=10 (01) (%s:%u)\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                __FILE__,
                __LINE__);
#endif
          // one beginning segment of SDU in PDU
          //LG rlc_um_send_sdu(rlc_pP,ctxt_pP->frame,ctxt_pP->enb_flag); // may be not necessary
          //!当前PDU中的first byte是SDU的first byte,但是结尾不是last,因此这个PDU只是一个SDU的开头
          //!由于E =0表示后面是数据域，因此这里的PDU 只能是一个SDU的部分数据 
          rlc_um_clear_rx_sdu(ctxt_pP, rlc_pP);
          rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size); 
		  //！这里只完成data 的copy，但是不向上层发送
          rlc_pP->reassembly_missing_sn_detected = 0;
          break;

        case RLC_FI_1ST_BYTE_DATA_IS_NOT_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
          LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU NO E_LI FI=01 (10) (%s:%u)\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                __FILE__,
                __LINE__);
#endif

          // one last segment of SDU
          if (rlc_pP->reassembly_missing_sn_detected == 0) {
		  	//！最后一个byte接收到，则上报SDU 
            rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size);
            rlc_um_send_sdu(ctxt_pP, rlc_pP);
          } else {
            //clear sdu already done
            rlc_pP->stat_rx_data_pdu_dropped += 1;
            rlc_pP->stat_rx_data_bytes_dropped += tb_ind_p->size;
          }

          rlc_pP->reassembly_missing_sn_detected = 0;
          break;

        case RLC_FI_1ST_BYTE_DATA_IS_NOT_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_NOT_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
          LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU NO E_LI FI=00 (11) (%s:%u)\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                __FILE__,
                __LINE__);
#endif

          if (rlc_pP->reassembly_missing_sn_detected == 0) {
            // one whole segment of SDU in PDU
            //！过来的是一个SDU 的中间部分数据，直接copy 
            rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size);
          } else {
           //！如果reassembly_missing_sn_detected = 1,说明之前的包丢失了，没有收到包含有数据头的包
#if TRACE_RLC_UM_DAR
            LOG_W(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU NO E_LI FI=00 (11) MISSING SN DETECTED (%s:%u)\n",
                  PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                  __FILE__,
                  __LINE__);
#endif
            //LOG_D(RLC, "[MSC_NBOX][FRAME %05u][%s][RLC_UM][MOD %u/%u][RB %u][Missing SN detected][RLC_UM][MOD %u/%u][RB %u]\n",
            //      ctxt_pP->frame, rlc_pP->module_id,rlc_pP->rb_id, rlc_pP->module_id,rlc_pP->rb_id);
            rlc_pP->reassembly_missing_sn_detected = 1; // not necessary but for readability of the code
            rlc_pP->stat_rx_data_pdu_dropped += 1;
            rlc_pP->stat_rx_data_bytes_dropped += tb_ind_p->size;
#if RLC_STOP_ON_LOST_PDU
            AssertFatal( rlc_pP->reassembly_missing_sn_detected == 1,
                         PROTOCOL_RLC_UM_CTXT_FMT" MISSING PDU DETECTED (%s:%u)\n",
                         PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                         __FILE__,
                         __LINE__);
#endif
          }

          break;

        default:
          //AssertFatal( 0 , PROTOCOL_RLC_UM_CTXT_FMT" fi=%d! TRY REASSEMBLY SHOULD NOT GO HERE (%s:%u)\n",
          //             PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          //             fi,
          //             __FILE__,
          //             __LINE__);
          LOG_E(RLC, PROTOCOL_RLC_UM_CTXT_FMT" fi=%d! TRY REASSEMBLY SHOULD NOT GO HERE (%s:%u)\n",
                     PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP), fi, __FILE__, __LINE__);
          
        }
      } else {
       //!固定header 之后跟着的是扩展部分E+LI
       //!这里的size 是去掉了固定header 2byte之后的size 
       //！将LI存放再li_array中, 
       //! 将data_p 指向了data filed 
        if (rlc_um_read_length_indicators(&data_p, e_li_p, li_array, &num_li, &size ) >= 0) {
          switch (fi) {
          case RLC_FI_1ST_BYTE_DATA_IS_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
            LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU FI=11 (00) Li=",
                  PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));

            for (i=0; i < num_li; i++) {
              LOG_D(RLC, "%d ",li_array[i]);
            }

            LOG_D(RLC, " remaining size %d\n",size);
#endif
            // N complete SDUs
            //LGrlc_um_send_sdu(rlc_pP,ctxt_pP->frame,ctxt_pP->enb_flag);
            rlc_um_clear_rx_sdu(ctxt_pP, rlc_pP);

            //！此时第一个byte是一个SDU的first byte
            //！ 并且最后一个Byte是一个SDU的last byte 
            //!说明存在多个完整的SDU 
            for (i = 0; i < num_li; i++) {
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, li_array[i]);
              rlc_um_send_sdu(ctxt_pP, rlc_pP);
              data_p = &data_p[li_array[i]]; //!更新地址
            }
            //！最后一个data segment 没有LI,所以直接处理，
            //！这里的size 是已经从总的大小中减去了所有LI 的值
            if (size > 0) { // normally should always be > 0 but just for help debug
              // data_p is already ok, done by last loop above
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size);
              rlc_um_send_sdu(ctxt_pP, rlc_pP);  //!最后一个data segment 也是完整的PDU 
            }

            rlc_pP->reassembly_missing_sn_detected = 0;
            break;

          case RLC_FI_1ST_BYTE_DATA_IS_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_NOT_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
            LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU FI=10 (01) Li=",
                  PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));

            for (i=0; i < num_li; i++) {
              LOG_D(RLC, "%d ",li_array[i]);
            }

            LOG_D(RLC, " remaining size %d\n",size);
#endif
            // N complete SDUs + one segment of SDU in PDU
            //LG rlc_um_send_sdu(rlc_pP,ctxt_pP->frame,ctxt_pP->enb_flag);
            rlc_um_clear_rx_sdu(ctxt_pP, rlc_pP);

             //!前面的SDU都是完整的，直接整理并发送
            for (i = 0; i < num_li; i++) {
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, li_array[i]);
              rlc_um_send_sdu(ctxt_pP, rlc_pP);
              data_p = &data_p[li_array[i]];
            }
            //！最后一个data segment是不完整的SDU，所以只copy数据，不上报
            if (size > 0) { // normally should always be > 0 but just for help debug
              // data_p is already ok, done by last loop above
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size);
            }

            rlc_pP->reassembly_missing_sn_detected = 0; //！这里要清0
            break;

          case RLC_FI_1ST_BYTE_DATA_IS_NOT_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
            LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU FI=01 (10) Li=",
                  PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));

            for (i=0; i < num_li; i++) {
              LOG_D(RLC, "%d ",li_array[i]);
            }

            LOG_D(RLC, " remaining size %d\n",size);
#endif
            //!因为这里有多个segment ,也就是在一个PDU上有多个SDU,并且最后一个byte是SDU的last byte
            //!因此这里只能是第一个segment出现了丢包，其他的SDU 包都是完整的。
            if (rlc_pP->reassembly_missing_sn_detected) {  //如果丢包过，则丢弃这个SDU 
              reassembly_start_index = 1;
              data_p = &data_p[li_array[0]];
              //rlc_pP->stat_rx_data_pdu_dropped += 1;
              rlc_pP->stat_rx_data_bytes_dropped += li_array[0];
            } else {
              reassembly_start_index = 0;
            }

            // one last segment of SDU + N complete SDUs in PDU
            for (i = reassembly_start_index; i < num_li; i++) {
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, li_array[i]);
              rlc_um_send_sdu(ctxt_pP, rlc_pP);
              data_p = &data_p[li_array[i]];
            }
           
            if (size > 0) { // normally should always be > 0 but just for help debug
              // data_p is already ok, done by last loop above
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size);
              rlc_um_send_sdu(ctxt_pP, rlc_pP);
            }

            rlc_pP->reassembly_missing_sn_detected = 0;
            break;

          case RLC_FI_1ST_BYTE_DATA_IS_NOT_1ST_BYTE_SDU_LAST_BYTE_DATA_IS_NOT_LAST_BYTE_SDU:
#if TRACE_RLC_UM_DAR
            LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRY REASSEMBLY PDU FI=00 (11) Li=",
                  PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));

            for (i=0; i < num_li; i++) {
              LOG_D(RLC, "%d ",li_array[i]);
            }

            LOG_D(RLC, " remaining size %d\n",size);
#endif
             //！这种情况，说明第一个包是个半截包，最后一个包也是个半截包，中间的包是完整的
             //! 如果出现了丢包，那么只能是第一个包丢了
            if (rlc_pP->reassembly_missing_sn_detected) {
#if TRACE_RLC_UM_DAR
              LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" DISCARD FIRST LI %d (%s:%u)",
                    PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                    li_array[0],
                    __FILE__,
                    __LINE__);
#endif
              reassembly_start_index = 1;
              data_p = &data_p[li_array[0]];
              //rlc_pP->stat_rx_data_pdu_dropped += 1;
              rlc_pP->stat_rx_data_bytes_dropped += li_array[0];
            } else {
              reassembly_start_index = 0;
            }
             //！将中间的包都上报
            for (i = reassembly_start_index; i < num_li; i++) {
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, li_array[i]);
              rlc_um_send_sdu(ctxt_pP, rlc_pP);
              data_p = &data_p[li_array[i]];
            }

            if (size > 0) { // normally should always be > 0 but just for help debug
              // data_p is already ok, done by last loop above
              rlc_um_reassembly (ctxt_pP, rlc_pP, data_p, size); //！最后一个包是半截包 
            } else {
              //AssertFatal( 0 !=0, PROTOCOL_RLC_UM_CTXT_FMT" size=%d! SHOULD NOT GO HERE (%s:%u)\n",
              //             PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
              //             size,
              //             __FILE__,
              //             __LINE__);
              LOG_E(RLC, PROTOCOL_RLC_UM_CTXT_FMT" size=%d! SHOULD NOT GO HERE (%s:%u)\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP), size, __FILE__, __LINE__);
              
              //rlc_pP->stat_rx_data_pdu_dropped += 1;
              rlc_pP->stat_rx_data_bytes_dropped += size;
            }

            rlc_pP->reassembly_missing_sn_detected = 0;
            break;

          default:
#if TRACE_RLC_UM_DAR
            LOG_W(RLC, PROTOCOL_RLC_UM_CTXT_FMT" Missing SN detected (%s:%u)\n",
                  PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                  __FILE__,
                  __LINE__);
#endif
            rlc_pP->stat_rx_data_pdu_dropped += 1;
            rlc_pP->stat_rx_data_bytes_dropped += tb_ind_p->size;

            rlc_pP->reassembly_missing_sn_detected = 1;
#if RLC_STOP_ON_LOST_PDU
            AssertFatal( rlc_pP->reassembly_missing_sn_detected == 1,
                         PROTOCOL_RLC_UM_CTXT_FMT" MISSING PDU DETECTED (%s:%u)\n",
                         PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                         __FILE__,
                         __LINE__);
#endif
          }
        } else {
          rlc_pP->stat_rx_data_pdu_dropped += 1;
          rlc_pP->stat_rx_data_bytes_dropped += tb_ind_p->size;
          rlc_pP->reassembly_missing_sn_detected = 1;
           //！header错了
          LOG_W(RLC, "[SN %d] Bad RLC header! Discard this RLC PDU (size=%d)\n", sn, size);
        }
      }

#if TRACE_RLC_UM_DAR
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" REMOVE PDU FROM DAR BUFFER  SN=%03d (%s:%u)\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            sn,
            __FILE__,
            __LINE__);
#endif
       //！将这个SN对应的memory 从dar_buffer中释放
      free_mem_block(rlc_pP->dar_buffer[sn], __func__);
      rlc_pP->dar_buffer[sn] = NULL;
    } else {
	 //！如果从dar_buffer中没有找到SN对应的data,则认为丢失了data 
      rlc_pP->last_reassemblied_missing_sn = sn;
#if TRACE_RLC_UM_DAR
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" Missing SN %04d detected, clearing RX SDU (%s:%u)\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            sn,
            __FILE__,
            __LINE__);
#endif
      rlc_pP->reassembly_missing_sn_detected = 1;  //!置位flag 
      rlc_um_clear_rx_sdu(ctxt_pP, rlc_pP);
#if RLC_STOP_ON_LOST_PDU
      AssertFatal( rlc_pP->reassembly_missing_sn_detected == 1,
                   PROTOCOL_RLC_UM_CTXT_FMT" MISSING PDU DETECTED (%s:%u)\n",
                   PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                   __FILE__,
                   __LINE__);
#endif
    }

	//!SN 向上加，如果出现了接收窗SN号翻转的情况怎么处理？ 

    sn = (sn + 1) % rlc_pP->rx_sn_modulo;

    if ((sn == rlc_pP->vr_uh) || (sn == end_snP)) {
      continue_reassembly = 0;
    }
  }

#if TRACE_RLC_UM_DAR
  LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TRIED REASSEMBLY VR(UR)=%03d VR(UX)=%03d VR(UH)=%03d (%s:%u)\n",
        PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
        rlc_pP->vr_ur,
        rlc_pP->vr_ux,
        rlc_pP->vr_uh,
        __FILE__,
        __LINE__);
#endif

  VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_TRY_REASSEMBLY,VCD_FUNCTION_OUT);
}
//-----------------------------------------------------------------------------
void
rlc_um_stop_and_reset_timer_reordering(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t *            rlc_pP)
{
#if TRACE_RLC_UM_DAR
  LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" [T-REORDERING] STOPPED AND RESET\n",
        PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));
#endif
  rlc_pP->t_reordering.running         = 0;
  rlc_pP->t_reordering.ms_time_out     = 0;
  rlc_pP->t_reordering.ms_start        = 0;
  rlc_pP->t_reordering.timed_out       = 0;
}
//-----------------------------------------------------------------------------
void
rlc_um_start_timer_reordering(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t *            rlc_pP)
{
  rlc_pP->t_reordering.timed_out       = 0;

  if (rlc_pP->t_reordering.ms_duration > 0) {
  rlc_pP->t_reordering.running         = 1;
    //!设置durtion 之后超时
    rlc_pP->t_reordering.ms_time_out      = PROTOCOL_CTXT_TIME_MILLI_SECONDS(ctxt_pP) + rlc_pP->t_reordering.ms_duration;
     //！设置起始时刻从当前帧开始
	rlc_pP->t_reordering.ms_start        = PROTOCOL_CTXT_TIME_MILLI_SECONDS(ctxt_pP);
#if TRACE_RLC_UM_DAR
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" [T-REORDERING] STARTED (TIME-OUT = FRAME %05u)\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
        rlc_pP->t_reordering.ms_time_out);
#endif
  } else {
    LOG_T(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[T-REORDERING] NOT STARTED, CAUSE CONFIGURED 0 ms\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP));
  }
}
//-----------------------------------------------------------------------------
void
rlc_um_init_timer_reordering(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t * const rlc_pP,
  const uint32_t  ms_durationP)
{
  rlc_pP->t_reordering.running         = 0;
  rlc_pP->t_reordering.ms_time_out     = 0;
  rlc_pP->t_reordering.ms_start        = 0;
  rlc_pP->t_reordering.ms_duration     = ms_durationP;
  rlc_pP->t_reordering.timed_out       = 0;
}
//-----------------------------------------------------------------------------
//!
//
void rlc_um_check_timer_dar_time_out(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t * const rlc_pP)
{
  signed int     in_window;
  rlc_usn_t      old_vr_ur;


  VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_CHECK_TIMER_DAR_TIME_OUT,VCD_FUNCTION_IN);
  
  if ((rlc_pP->t_reordering.running)) {
    if (
		//!下面这两种情况都算超时 
      // CASE 1:          start              time out
      //        +-----------+------------------+----------+
      //        |           |******************|          |
      //        +-----------+------------------+----------+
      //FRAME # 0                                     FRAME MAX
      ((rlc_pP->t_reordering.ms_start < rlc_pP->t_reordering.ms_time_out) &&
       ((PROTOCOL_CTXT_TIME_MILLI_SECONDS(ctxt_pP) >= rlc_pP->t_reordering.ms_time_out) ||
        (PROTOCOL_CTXT_TIME_MILLI_SECONDS(ctxt_pP) < rlc_pP->t_reordering.ms_start)))      ||
      // CASE 2:        time out            start
      //        +-----------+------------------+----------+
      //        |***********|                  |**********|
      //        +-----------+------------------+----------+
      //FRAME # 0                                     FRAME MAX VALUE
      ((rlc_pP->t_reordering.ms_start > rlc_pP->t_reordering.ms_time_out) &&
       (PROTOCOL_CTXT_TIME_MILLI_SECONDS(ctxt_pP) < rlc_pP->t_reordering.ms_start) &&
       (PROTOCOL_CTXT_TIME_MILLI_SECONDS(ctxt_pP) >= rlc_pP->t_reordering.ms_time_out))
    ) {

      //if ((uint32_t)((uint32_t)rlc_pP->timer_reordering  + (uint32_t)rlc_pP->timer_reordering_init)   <= ctxt_pP->frame) {
      // 5.1.2.2.4   Actions when t-Reordering expires
      //  When t-Reordering expires, the receiving UM RLC entity shall:
      //  -update VR(UR) to the SN of the first UMD PDU with SN >= VR(UX) that has not been received;
      //  -reassemble RLC SDUs from any UMD PDUs with SN < updated VR(UR), remove RLC headers when doing so and deliver the reassembled RLC SDUs to upper layer in ascending order of the RLC SN if not delivered before;
      //  -if VR(UH) > VR(UR):
      //      -start t-Reordering;
      //      -set VR(UX) to VR(UH).
      rlc_pP->stat_timer_reordering_timed_out += 1;
#if TRACE_RLC_UM_DAR
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT"*****************************************************\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT"*    T I M E  -  O U T                              *\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT"*****************************************************\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" TIMER t-Reordering expiration\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP));
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" timer_reordering=%d frame=%d expire ms %d\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            rlc_pP->t_reordering.ms_duration,
            ctxt_pP->frame,
            rlc_pP->t_reordering.ms_time_out);
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" set VR(UR)=%03d to",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            rlc_pP->vr_ur);
#endif

      if (pthread_mutex_trylock(&rlc_pP->lock_dar_buffer) == 0) {
	  	//！超时后的处理，将Ux之前的PDU都不再接收了，要么上报，要么丢弃
        old_vr_ur   = rlc_pP->vr_ur;

        //从ux开始，往上一直找一个没有接收到的SN，作为新的UR,更新UR,后续就处理新的
        //!UR以下的SDU 
        rlc_pP->vr_ur = rlc_pP->vr_ux; 
        while (rlc_um_get_pdu_from_dar_buffer(ctxt_pP, rlc_pP, rlc_pP->vr_ur)) {
          rlc_pP->vr_ur = (rlc_pP->vr_ur+1)%rlc_pP->rx_sn_modulo;
        }

#if TRACE_RLC_UM_DAR
        LOG_D(RLC, " %d", rlc_pP->vr_ur);
        LOG_D(RLC, "\n");
#endif
        //！开始处理更新后的UR以下的SDU ，从旧的UR 开始一直处理到新的UR 
        rlc_um_try_reassembly(ctxt_pP, rlc_pP ,old_vr_ur, rlc_pP->vr_ur);

        //!这里需要判断uh>ur, 并且uh = uh时就会返回2，所以根据协议，要重启timer,并更新ux = uh 
        in_window = rlc_um_in_window(ctxt_pP, rlc_pP, rlc_pP->vr_ur,  rlc_pP->vr_uh,  rlc_pP->vr_uh);
         //!
        if (in_window == 2) {
          rlc_um_start_timer_reordering(ctxt_pP, rlc_pP); //！重启timer 
          rlc_pP->vr_ux = rlc_pP->vr_uh; 
#if TRACE_RLC_UM_DAR
          LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" restarting t-Reordering set VR(UX) to %d (VR(UH)>VR(UR))\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                rlc_pP->vr_ux);
#endif
        } else {
#if TRACE_RLC_UM_DAR
          LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" STOP t-Reordering VR(UX) = %03d\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
                rlc_pP->vr_ux);
#endif
          rlc_um_stop_and_reset_timer_reordering(ctxt_pP, rlc_pP);
        }

        RLC_UM_MUTEX_UNLOCK(&rlc_pP->lock_dar_buffer);
      }
    }
  }

  VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_CHECK_TIMER_DAR_TIME_OUT,VCD_FUNCTION_OUT);
}
//-----------------------------------------------------------------------------
mem_block_t*
rlc_um_remove_pdu_from_dar_buffer(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t * const rlc_pP,
  rlc_usn_t snP)
{
  mem_block_t * pdu_p     = rlc_pP->dar_buffer[snP];
#if TRACE_RLC_UM_DAR
  LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" REMOVE PDU FROM DAR BUFFER  SN=%03d\n",
        PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
        snP);
#endif
  rlc_pP->dar_buffer[snP] = NULL;
  return pdu_p;
}
//-----------------------------------------------------------------------------
mem_block_t*
rlc_um_get_pdu_from_dar_buffer(const protocol_ctxt_t* const ctxt_pP, rlc_um_entity_t * const rlc_pP, rlc_usn_t snP)
{
  return rlc_pP->dar_buffer[snP];
}
//-----------------------------------------------------------------------------
void
rlc_um_store_pdu_in_dar_buffer(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t * const rlc_pP,
  mem_block_t *pdu_pP,
  rlc_usn_t snP)
{
#if TRACE_RLC_UM_DAR
  LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" STORE PDU IN DAR BUFFER  SN=%03d  VR(UR)=%03d VR(UX)=%03d VR(UH)=%03d\n",
        PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
        snP,
        rlc_pP->vr_ur,
        rlc_pP->vr_ux,
        rlc_pP->vr_uh);
#endif
  rlc_pP->dar_buffer[snP] = pdu_pP;
}
//-----------------------------------------------------------------------------
// returns -2 if lower_bound  > sn
// returns -1 if higher_bound < sn
// returns  0 if lower_bound  < sn < higher_bound
// returns  1 if lower_bound  == sn
// returns  2 if higher_bound == sn
// returns  3 if higher_bound == sn == lower_bound
//！这个函数并不是按照协议去一次性判断SN 是否在接收窗内的，
//！而是自定义了窗的下边界和上边界，将协议里的接收窗分成了几部分进行处理

signed int
rlc_um_in_window(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t * const rlc_pP,
  rlc_sn_t lower_boundP,  //! UH - window_size是窗的下边界 
  rlc_sn_t snP,           //！当前要处理的SN号
  rlc_sn_t higher_boundP) 
{
  rlc_sn_t modulus = (rlc_sn_t)rlc_pP->vr_uh - rlc_pP->rx_um_window_size;  //！这是整个接收窗的下边界
#if TRACE_RLC_UM_RX
  rlc_sn_t     lower_bound  = lower_boundP;
  rlc_sn_t     higher_bound = higher_boundP;
  rlc_sn_t     sn           = snP;
#endif

  //！本次这个分段接收窗和上下边界和SNP 都分别和真正的下边界做减法，归一化。 
  lower_boundP  = (lower_boundP  - modulus) % rlc_pP->rx_sn_modulo;  //！rx_sn_modulo = 1024
  higher_boundP = (higher_boundP - modulus) % rlc_pP->rx_sn_modulo;
  snP           = (snP           - modulus) % rlc_pP->rx_sn_modulo; 

  if ( lower_boundP > snP) {  //SN 不在接收窗内
#if TRACE_RLC_UM_RX
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d not in WINDOW[%03d:%03d] (SN<LOWER BOUND)\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn,
          lower_bound,
          higher_bound);
#endif
    return -2;
  }

  if ( higher_boundP < snP) { //!< 说明本次处理的PDU 不在这段接收窗内
#if TRACE_RLC_UM_RX
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d not in WINDOW[%03d:%03d] (SN>HIGHER BOUND) <=> %d not in WINDOW[%03d:%03d]\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn,
          lower_bound,
          higher_bound,
          snP,
          lower_boundP,
          higher_boundP);
#endif
    return -1;
  }
   //!PDU 处于本段接收窗的下边界，返回1，如果上下边界相等了，那么说明窗不合适，返回3 
  if ( lower_boundP == snP) {
    if ( higher_boundP == snP) {
#if TRACE_RLC_UM_RX
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d  in WINDOW[%03d:%03d] (SN=HIGHER BOUND=LOWER BOUND)\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            sn,
            lower_bound,
            higher_bound);
#endif
      return 3;
    }

#if TRACE_RLC_UM_RX
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d  in WINDOW[%03d:%03d] (SN=LOWER BOUND)\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn,
          lower_bound,
          higher_bound);
#endif
    return 1;
  }

  //！SN 在上边界了，则返回2
  if ( higher_boundP == snP) {
#if TRACE_RLC_UM_RX
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d  in WINDOW[%03d:%03d] (SN=HIGHER BOUND)\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn,
          lower_bound,
          higher_bound);
#endif
    return 2;
  }

  return 0; //!正常返回0

}
//-----------------------------------------------------------------------------

//! recoding window, 按照协议，[UH -window_size: UH]

signed int
rlc_um_in_reordering_window(
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t * const rlc_pP,
  const rlc_sn_t snP)
{
  rlc_sn_t   modulus = (signed int)rlc_pP->vr_uh - rlc_pP->rx_um_window_size;
  rlc_sn_t   sn_mod = (snP - modulus) % rlc_pP->rx_sn_modulo;

  if ( 0 <= sn_mod) {  //在recoding window的下边界之上
     //在recoding window 以内，返回0 
    if (sn_mod < rlc_pP->rx_um_window_size) {
#if TRACE_RLC_UM_DAR
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d IN REORDERING WINDOW[%03d:%03d[ SN %d IN [%03d:%03d[ VR(UR)=%03d VR(UH)=%03d\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            sn_mod,
            0,
            rlc_pP->rx_um_window_size,
            snP,
            (signed int)rlc_pP->vr_uh - rlc_pP->rx_um_window_size,
            rlc_pP->vr_uh,
            rlc_pP->vr_ur,
            rlc_pP->vr_uh);
#endif
      return 0;
    }
  }

#if TRACE_RLC_UM_DAR

  if (modulus < 0) { //！uh 还小于512，这里的接收窗是个循环窗，所以此时的接收窗的边界应该是：[]uh + 512,...uh]
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d NOT IN REORDERING WINDOW[%03d:%03d[ SN %d NOT IN [%03d:%03d[ VR(UR)=%03d VR(UH)=%03d\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn_mod,
          modulus + 1024,
          rlc_pP->rx_um_window_size,
          snP,
          modulus + 1024 ,
          rlc_pP->vr_uh,
          rlc_pP->vr_ur,
          rlc_pP->vr_uh);
  } else { //！uh 大于512了，此时的接收窗的大小是[uh-512,uh]
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" %d NOT IN REORDERING WINDOW[%03d:%03d[ SN %d NOT IN [%03d:%03d[ VR(UR)=%03d VR(UH)=%03d\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn_mod,
          modulus,
          rlc_pP->rx_um_window_size,
          snP,
          modulus ,
          rlc_pP->vr_uh,
          rlc_pP->vr_ur,
          rlc_pP->vr_uh);
  }

#endif
  return -1;
}
//-----------------------------------------------------------------------------
void
rlc_um_receive_process_dar (
  const protocol_ctxt_t* const ctxt_pP,
  rlc_um_entity_t * const      rlc_pP,
  mem_block_t *                pdu_mem_pP,
  rlc_um_pdu_sn_10_t * const   pdu_pP,
  const sdu_size_t             tb_sizeP)
{
  // 36.322v9.3.0 section 5.1.2.2.1:
  // The receiving UM RLC entity shall maintain a reordering window according to state variable VR(UH) as follows:
  //      -a SN falls within the reordering window if (VR(UH) – UM_Window_Size) <= SN < VR(UH);
  //      -a SN falls outside of the reordering window otherwise.
  // When receiving an UMD PDU from lower layer, the receiving UM RLC entity shall:
  //      -either discard the received UMD PDU or place it in the reception buffer (see sub clause 5.1.2.2.2);
  //      -if the received UMD PDU was placed in the reception buffer:
  //          -update state variables, reassemble and deliver RLC SDUs to upper layer and start/stop t-Reordering as needed (see sub clause 5.1.2.2.3);
  // When t-Reordering expires, the receiving UM RLC entity shall:
  // -   update state variables, reassemble and deliver RLC SDUs to upper layer and start t-Reordering as needed (see sub clause 5.1.2.2.4).



  // When an UMD PDU with SN = x is received from lower layer, the receiving UM RLC entity shall:
  // -if VR(UR) < x < VR(UH) and the UMD PDU with SN = x has been received before; or
  // -if (VR(UH) – UM_Window_Size) <= x < VR(UR):
  //      -discard the received UMD PDU;
  // -else:
  //      -place the received UMD PDU in the reception buffer.

  rlc_sn_t sn = -1;
  signed int in_window;

  VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_RECEIVE_PROCESS_DAR, VCD_FUNCTION_IN);

  if (rlc_pP->rx_sn_length == 10) {
    sn = ((pdu_pP->b1 & 0x00000003) << 8) + pdu_pP->b2; //!获取SN 
  } else if (rlc_pP->rx_sn_length == 5) {
    sn = pdu_pP->b1 & 0x1F;
  } else {
    free_mem_block(pdu_mem_pP, __func__);
  }

  RLC_UM_MUTEX_LOCK(&rlc_pP->lock_dar_buffer, ctxt_pP, rlc_pP); //!加线程锁
   //！vr_ur 表示的是还没有收到PDU 的最小SN号
   //! 这里调用rlc_um_in_window 是用来判断： 
   //！PDU 是否在[uh-window_size,ur] 这个范围内的
   //! uh-window_size < SN < ur, 返回0
   //！uh-window-size = SN        返回1
   //！                  SN = ur  返回2
  in_window = rlc_um_in_window(ctxt_pP, rlc_pP, rlc_pP->vr_uh - rlc_pP->rx_um_window_size, sn, rlc_pP->vr_ur);

#if TRACE_RLC_PAYLOAD
  rlc_util_print_hex_octets(RLC, &pdu_pP->b1, tb_sizeP);
#endif

  // rlc_um_in_window() returns -2 if lower_bound  > sn
  // rlc_um_in_window() returns -1 if higher_bound < sn
  // rlc_um_in_window() returns  0 if lower_bound  < sn < higher_bound
  // rlc_um_in_window() returns  1 if lower_bound  == sn
  // rlc_um_in_window() returns  2 if higher_bound == sn
  // rlc_um_in_window() returns  3 if higher_bound == sn == lower_bound
  if ((in_window == 1) || (in_window == 0)) { 
#if TRACE_RLC_UM_DAR
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" RX PDU  VR(UH) – UM_Window_Size) <= SN %d < VR(UR) -> GARBAGE\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn);
#endif
    //! 这里说明SN <= UR, 按照协议，UR 以下的PDU 应该不用再接收了， 所以认为可以丢弃，直接return
    rlc_pP->stat_rx_data_pdu_out_of_window   += 1; //！记录出窗的个数
    rlc_pP->stat_rx_data_bytes_out_of_window += tb_sizeP;
    free_mem_block(pdu_mem_pP, __func__);
    pdu_mem_pP = NULL;
    RLC_UM_MUTEX_UNLOCK(&rlc_pP->lock_dar_buffer);
    VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_RECEIVE_PROCESS_DAR, VCD_FUNCTION_OUT);
    return;
  }
  
  if ((rlc_um_get_pdu_from_dar_buffer(ctxt_pP, rlc_pP, sn))) {
  	 //!如果能从dar buffer 中获取到，并且PDU在[UR, UH ]这段窗内，说明之前已经收到过了，这次收到的是重复的PDU 
    in_window = rlc_um_in_window(ctxt_pP, rlc_pP, rlc_pP->vr_ur, sn, rlc_pP->vr_uh);

    if (in_window == 0) {  //如果在，说明重复了，也要丢弃
#if TRACE_RLC_UM_DAR
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" RX PDU  VR(UR) < SN %d < VR(UH) and RECEIVED BEFORE-> GARBAGE\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            sn);
#endif
      //discard the PDU
      rlc_pP->stat_rx_data_pdus_duplicate  += 1;  //！记录重复的个数
      rlc_pP->stat_rx_data_bytes_duplicate += tb_sizeP;
      free_mem_block(pdu_mem_pP, __func__);
      pdu_mem_pP = NULL;
      RLC_UM_MUTEX_UNLOCK(&rlc_pP->lock_dar_buffer);
      VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_RECEIVE_PROCESS_DAR, VCD_FUNCTION_OUT);
      return;
    }

	 //如果不在[UR,UH]这段内，但是能从dar_buffer中获取，那么也是重复的，

    // 2 lines to avoid memory leaks
    rlc_pP->stat_rx_data_pdus_duplicate  += 1;
    rlc_pP->stat_rx_data_bytes_duplicate += tb_sizeP;
#if TRACE_RLC_UM_DAR
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" RX PDU SN %03d REMOVE OLD PDU BEFORE STORING NEW PDU\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn);
#endif
    mem_block_t *pdu = rlc_um_remove_pdu_from_dar_buffer(ctxt_pP, rlc_pP, sn); //！将重复的PDU的old 数据丢弃
    free_mem_block(pdu, __func__);
  }


  //！将数据存入到dar buffer中
  rlc_um_store_pdu_in_dar_buffer(ctxt_pP, rlc_pP, pdu_mem_pP, sn);


  // -if x falls outside of the reordering window:
  //      -update VR(UH) to x + 1;
  //      -reassemble RLC SDUs from any UMD PDUs with SN that falls outside of
  //       the reordering window, remove RLC headers when doing so and deliver
  //       the reassembled RLC SDUs to upper layer in ascending order of the
  //       RLC SN if not delivered before;
  //
  //      -if VR(UR) falls outside of the reordering window:
  //          -set VR(UR) to (VR(UH) – UM_Window_Size);
  
   //!前面已经验证了SN 是否在UR 以下，是否是重复的 
   //!如果SN 不在recording 窗内，返回-1，否则返回0
  if (rlc_um_in_reordering_window(ctxt_pP, rlc_pP, sn) < 0) {
#if TRACE_RLC_UM_DAR
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" RX PDU  SN %d OUTSIDE REORDERING WINDOW VR(UH)=%d UM_Window_Size=%d\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
          sn,
          rlc_pP->vr_uh,
          rlc_pP->rx_um_window_size);
#endif
    //！更新UH
    rlc_pP->vr_uh = (sn + 1) % rlc_pP->rx_sn_modulo;
    //!<如果ur 在recording 窗外，则表示需要处理窗外的PDU了。
    if (rlc_um_in_reordering_window(ctxt_pP, rlc_pP, rlc_pP->vr_ur) != 0) {
		//如果UR 也被移出到窗外了，那么更新UR = UH - WINDOWSIZE 
		//这里相当于是下边界
      in_window = rlc_pP->vr_uh - rlc_pP->rx_um_window_size;

      if (in_window < 0) {
        in_window = in_window + rlc_pP->rx_sn_modulo;
      }
       //！处理从ur开始，依次SN 递增的处理
       //这里要注意in_window > ur这种特殊情况
       //！这里如果ur = 1,但是uh =2,然后接收窗 = -510，in_window=514, 
       //! 上述情况下，实际的接收窗应该是从【514 ----1023，2】，但是代码处理的是2-514 这段，这里有问题
      rlc_um_try_reassembly(ctxt_pP, rlc_pP, rlc_pP->vr_ur, in_window);
    }

    
    if (rlc_um_in_reordering_window(ctxt_pP, rlc_pP, rlc_pP->vr_ur) < 0) {
#if TRACE_RLC_UM_DAR
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" VR(UR) %d OUTSIDE REORDERING WINDOW SET TO VR(UH) – UM_Window_Size = %d\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            rlc_pP->vr_ur,
            in_window);
#endif
      rlc_pP->vr_ur = in_window; //！更新ur = uh - window-size
    }
  }

  // -if the reception buffer contains an UMD PDU with SN = VR(UR):
  //      -update VR(UR) to the SN of the first UMD PDU with SN > current
  //          VR(UR) that has not been received;
  //      -reassemble RLC SDUs from any UMD PDUs with SN < updated VR(UR),
  //          remove RLC headers when doing so and deliver the reassembled RLC
  //          SDUs to upper layer in ascending order of the RLC SN if not
  //          delivered before;

  //！如果sn =ur,并且ur的PDU已经收到过，
  if ((sn == rlc_pP->vr_ur) && rlc_um_get_pdu_from_dar_buffer(ctxt_pP, rlc_pP, rlc_pP->vr_ur)) {
    //sn_tmp = rlc_pP->vr_ur;
    do { //！从ur 开始依次往上找，直到找到一个没有收到PDU的SN号，并且不能等于UH 
      rlc_pP->vr_ur = (rlc_pP->vr_ur+1) % rlc_pP->rx_sn_modulo;
    } while (rlc_um_get_pdu_from_dar_buffer(ctxt_pP, rlc_pP, rlc_pP->vr_ur) && (rlc_pP->vr_ur != rlc_pP->vr_uh));
     //!将SN < 更新后的ur 的PDU,进行去header处理，从SN 往上处理，处理到更新后的UR结束。
    rlc_um_try_reassembly(ctxt_pP, rlc_pP, sn, rlc_pP->vr_ur);
  }

  // -if t-Reordering is running:
  //      -if VR(UX) <= VR(UR); or
  //      -if VR(UX) falls outside of the reordering window and VR(UX) is not
  //          equal to VR(UH)::
  //          -stop and reset t-Reordering;
  
  if (rlc_pP->t_reordering.running) {
  	// 如果ux != uh,并且在ux 在recording windows之外，那么停止并重置timer 
    if (rlc_pP->vr_uh != rlc_pP->vr_ux) {
      in_window = rlc_um_in_reordering_window(ctxt_pP, rlc_pP, rlc_pP->vr_ux);

      if (in_window < 0) {
#if TRACE_RLC_UM_DAR
        LOG_D(RLC,
              PROTOCOL_RLC_UM_CTXT_FMT" STOP and RESET t-Reordering because VR(UX) falls outside of the reordering window and VR(UX)=%d is not equal to VR(UH)=%d -or- VR(UX) <= VR(UR)\n",
              PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
              rlc_pP->vr_ux,
              rlc_pP->vr_uh);
#endif
        rlc_um_stop_and_reset_timer_reordering(ctxt_pP, rlc_pP);
      }
    }
  }

  if (rlc_pP->t_reordering.running) {
    in_window = rlc_um_in_window(ctxt_pP, rlc_pP, rlc_pP->vr_ur,  rlc_pP->vr_ux,  rlc_pP->vr_uh);
     //！ -2： ux < ur, 丢失ux,不用再运行timer 
     //! 1:    ux = ur ,表示已经收到了，也不用再运行了
    if ((in_window == -2) || (in_window == 1)) {
#if TRACE_RLC_UM_DAR
      LOG_D(RLC,
            PROTOCOL_RLC_UM_CTXT_FMT" STOP and RESET t-Reordering because VR(UX) falls outside of the reordering window and VR(UX)=%d is not equal to VR(UH)=%d\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            rlc_pP->vr_ux,
            rlc_pP->vr_uh);
#endif
      rlc_um_stop_and_reset_timer_reordering(ctxt_pP, rlc_pP);
    }
  }

  // -if t-Reordering is not running (includes the case when t-Reordering is
  //      stopped due to actions above):
  //      -if VR(UH) > VR(UR):
  //          -start t-Reordering;
  //          -set VR(UX) to VR(UH).

  if (rlc_pP->t_reordering.running == 0) {

    //！这里必然 =2啊
    in_window = rlc_um_in_window(ctxt_pP, rlc_pP, rlc_pP->vr_ur,  rlc_pP->vr_uh,  rlc_pP->vr_uh);

    if (in_window == 2) {
	  //!启动timer 
      rlc_um_start_timer_reordering(ctxt_pP, rlc_pP);
      rlc_pP->vr_ux = rlc_pP->vr_uh;  //！更新ux = uh
#if TRACE_RLC_UM_DAR
      LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" RESTART t-Reordering set VR(UX) to VR(UH) =%d\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP, rlc_pP),
            rlc_pP->vr_ux);
#endif
    }
  }

  RLC_UM_MUTEX_UNLOCK(&rlc_pP->lock_dar_buffer); //！解锁
  VCD_SIGNAL_DUMPER_DUMP_FUNCTION_BY_NAME(VCD_SIGNAL_DUMPER_FUNCTIONS_RLC_UM_RECEIVE_PROCESS_DAR, VCD_FUNCTION_OUT);
}
