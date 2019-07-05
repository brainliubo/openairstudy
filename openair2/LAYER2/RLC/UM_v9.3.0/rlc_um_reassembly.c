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
#define RLC_UM_REASSEMBLY_C 1
#include "platform_types.h"
//-----------------------------------------------------------------------------
#include <string.h>
#if ENABLE_ITTI
# include "platform_types.h"
# include "intertask_interface.h"
#endif
#include "assertions.h"
#include "rlc.h"
#include "rlc_um.h"
#include "rlc_primitives.h"
#include "list.h"
#include "LAYER2/MAC/mac_extern.h"
#include "common/utils/LOG/log.h"
#include "msc.h"

//-----------------------------------------------------------------------------
inline void
rlc_um_clear_rx_sdu (const protocol_ctxt_t* const ctxt_pP, rlc_um_entity_t* rlc_pP)
{
  rlc_pP->output_sdu_size_to_write = 0;
}

//-----------------------------------------------------------------------------
//!从mac buffer中拿出DATA来
void
rlc_um_reassembly (const protocol_ctxt_t* const ctxt_pP, rlc_um_entity_t *rlc_pP, uint8_t * src_pP, int32_t lengthP)
{
  sdu_size_t      sdu_max_size;

  LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[REASSEMBLY] reassembly()  %d bytes %d bytes already reassemblied\n",
        PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP),
        lengthP,
        rlc_pP->output_sdu_size_to_write);

  if (lengthP <= 0) {
    return;
  }
  
  if ((rlc_pP->is_data_plane)) {
    sdu_max_size = RLC_SDU_MAX_SIZE_DATA_PLANE;
  } else {
    sdu_max_size = RLC_SDU_MAX_SIZE_CONTROL_PLANE;
  }
   //！如果SDU 还没有申请BUFFER,则从MEM中申请一块SDU buffer,用来承载PDU的data filed 
  if (rlc_pP->output_sdu_in_construction == NULL) {
    //    msg("[RLC_UM_LITE] Getting mem_block ...\n");
    //! 从memory block 中获取一块free的memory ,获取的size大小为max_size 
    rlc_pP->output_sdu_in_construction = get_free_mem_block (sdu_max_size, __func__);
    rlc_pP->output_sdu_size_to_write = 0;
  }
  //！如果之前已经申请过buffer了，现在从偏移地址开始，把数据copy进去 
  if ((rlc_pP->output_sdu_in_construction)) {
    // check if no overflow in size
    if ((rlc_pP->output_sdu_size_to_write + lengthP) <= sdu_max_size) {
	 	
	 //！将PDU中的data field copy到SDU的buffer中 
      memcpy (&rlc_pP->output_sdu_in_construction->data[rlc_pP->output_sdu_size_to_write], src_pP, lengthP);
      rlc_pP->output_sdu_size_to_write += lengthP;
#if TRACE_RLC_UM_DISPLAY_ASCII_DATA
      rlc_pP->output_sdu_in_construction->data[rlc_pP->output_sdu_size_to_write] = 0;
      LOG_T(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[REASSEMBLY] DATA :",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP));
      rlc_util_print_hex_octets(RLC, (unsigned char*)rlc_pP->output_sdu_in_construction->data, rlc_pP->output_sdu_size_to_write);
#endif
    } else {

	//! MAC 上报的PDU 太大了，超出了SDU 的最大size 
#if STOP_ON_IP_TRAFFIC_OVERLOAD
      AssertFatal(0, PROTOCOL_RLC_UM_CTXT_FMT" RLC_UM_DATA_IND, SDU TOO BIG, DROPPED\n",
                  PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP));
#endif
      LOG_E(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[REASSEMBLY] [max_sdu size %d] ERROR  SDU SIZE OVERFLOW SDU GARBAGED\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP),
            sdu_max_size);
      // erase  SDU
      rlc_pP->output_sdu_size_to_write = 0;
    }
  } else {
   //！申请SDU buffer 失败
    LOG_E(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[REASSEMBLY]ERROR  OUTPUT SDU IS NULL\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP));
#if STOP_ON_IP_TRAFFIC_OVERLOAD
    AssertFatal(0, PROTOCOL_RLC_UM_CTXT_FMT" RLC_UM_DATA_IND, SDU DROPPED, OUT OF MEMORY\n",
                PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP));
#endif
  }

}
//-----------------------------------------------------------------------------
//！UM 发送SDU 
void
rlc_um_send_sdu (const protocol_ctxt_t* const ctxt_pP, rlc_um_entity_t *rlc_pP)
{
  if ((rlc_pP->output_sdu_in_construction)) {
    LOG_D(RLC, PROTOCOL_RLC_UM_CTXT_FMT" SEND_SDU to upper layers %d bytes sdu %p\n",
          PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP),
          rlc_pP->output_sdu_size_to_write,
          rlc_pP->output_sdu_in_construction);

    if (rlc_pP->output_sdu_size_to_write > 0) {
		//!已经有SDU了， 并且其中已经存放了PDU的数据， 
      rlc_pP->stat_rx_pdcp_sdu += 1;
      rlc_pP->stat_rx_pdcp_bytes += rlc_pP->output_sdu_size_to_write;

      MSC_LOG_TX_MESSAGE(
        (ctxt_pP->enb_flag == ENB_FLAG_YES) ? MSC_RLC_ENB:MSC_RLC_UE,
        (ctxt_pP->enb_flag == ENB_FLAG_YES) ? MSC_PDCP_ENB:MSC_PDCP_UE,
        (const char*)(rlc_pP->output_sdu_in_construction->data),
        rlc_pP->output_sdu_size_to_write,
        MSC_AS_TIME_FMT" "PROTOCOL_RLC_UM_MSC_FMT" DATA-IND size %u",
        MSC_AS_TIME_ARGS(ctxt_pP),
        PROTOCOL_RLC_UM_MSC_ARGS(ctxt_pP,rlc_pP),
        rlc_pP->output_sdu_size_to_write
      );

#if TEST_RLC_UM
#if TRACE_RLC_UM_DISPLAY_ASCII_DATA
      rlc_pP->output_sdu_in_construction->data[rlc_pP->output_sdu_size_to_write] = 0;
      LOG_T(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[SEND_SDU] DATA :",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP));
      rlc_util_print_hex_octets(RLC, rlc_pP->output_sdu_in_construction->data, rlc_pP->output_sdu_size_to_write);
#endif
      rlc_um_v9_3_0_test_data_ind (rlc_pP->module_id, rlc_pP->rb_id, rlc_pP->output_sdu_size_to_write, rlc_pP->output_sdu_in_construction);
#else
       
      // msg("[RLC] DATA IND ON MOD_ID %d RB ID %d, size %d\n",rlc_pP->module_id, rlc_pP->rb_id, ctxt_pP->frame,rlc_pP->output_sdu_size_to_write);
       //! //!正式代码：将RLC的数据上报给PDCP 
      rlc_data_ind (
        ctxt_pP,
        BOOL_NOT(rlc_pP->is_data_plane), //！是SRB,还是DRB 的flag
        rlc_pP->is_mxch,
        rlc_pP->rb_id,
        rlc_pP->output_sdu_size_to_write,
        rlc_pP->output_sdu_in_construction); //!在此函数中释放memory
#endif
      rlc_pP->output_sdu_in_construction = NULL;  //！释放指针
    } else {
      LOG_E(RLC, PROTOCOL_RLC_UM_CTXT_FMT"[SEND_SDU] ERROR SIZE <= 0 ... DO NOTHING, SET SDU SIZE TO 0\n",
            PROTOCOL_RLC_UM_CTXT_ARGS(ctxt_pP,rlc_pP));
    }

    rlc_pP->output_sdu_size_to_write = 0; //！清空当前实体的SDU size 
  }
}
