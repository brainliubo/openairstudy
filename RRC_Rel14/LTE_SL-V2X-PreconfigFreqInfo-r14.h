/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-Sidelink-Preconf"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SL_V2X_PreconfigFreqInfo_r14_H_
#define	_LTE_SL_V2X_PreconfigFreqInfo_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_SL-PreconfigGeneral-r12.h"
#include "LTE_SL-PreconfigV2X-RxPoolList-r14.h"
#include "LTE_SL-PreconfigV2X-TxPoolList-r14.h"
#include <NativeEnumerated.h>
#include "LTE_SL-Priority-r13.h"
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_SL_V2X_PreconfigFreqInfo_r14__syncPriority_r14 {
	LTE_SL_V2X_PreconfigFreqInfo_r14__syncPriority_r14_gnss	= 0,
	LTE_SL_V2X_PreconfigFreqInfo_r14__syncPriority_r14_enb	= 1
} e_LTE_SL_V2X_PreconfigFreqInfo_r14__syncPriority_r14;

/* Forward declarations */
struct LTE_SL_PreconfigV2X_Sync_r14;
struct LTE_SL_CommTxPoolSensingConfig_r14;
struct LTE_SL_ZoneConfig_r14;

/* LTE_SL-V2X-PreconfigFreqInfo-r14 */
typedef struct LTE_SL_V2X_PreconfigFreqInfo_r14 {
	LTE_SL_PreconfigGeneral_r12_t	 v2x_CommPreconfigGeneral_r14;
	struct LTE_SL_PreconfigV2X_Sync_r14	*v2x_CommPreconfigSync_r14;	/* OPTIONAL */
	LTE_SL_PreconfigV2X_RxPoolList_r14_t	 v2x_CommRxPoolList_r14;
	LTE_SL_PreconfigV2X_TxPoolList_r14_t	 v2x_CommTxPoolList_r14;
	LTE_SL_PreconfigV2X_TxPoolList_r14_t	 p2x_CommTxPoolList_r14;
	struct LTE_SL_CommTxPoolSensingConfig_r14	*v2x_ResourceSelectionConfig_r14;	/* OPTIONAL */
	struct LTE_SL_ZoneConfig_r14	*zoneConfig_r14;	/* OPTIONAL */
	long	 syncPriority_r14;
	LTE_SL_Priority_r13_t	*thresSL_TxPrioritization_r14;	/* OPTIONAL */
	long	*offsetDFN_r14;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SL_V2X_PreconfigFreqInfo_r14_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_syncPriority_r14_9;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SL_V2X_PreconfigFreqInfo_r14;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_SL_V2X_PreconfigFreqInfo_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SL_V2X_PreconfigFreqInfo_r14_1[10];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SL-PreconfigV2X-Sync-r14.h"
#include "LTE_SL-CommTxPoolSensingConfig-r14.h"
#include "LTE_SL-ZoneConfig-r14.h"

#endif	/* _LTE_SL_V2X_PreconfigFreqInfo_r14_H_ */
#include <asn_internal.h>
