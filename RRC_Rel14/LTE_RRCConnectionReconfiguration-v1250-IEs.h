/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RRCConnectionReconfiguration_v1250_IEs_H_
#define	_LTE_RRCConnectionReconfiguration_v1250_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "LTE_WLAN-OffloadConfig-r12.h"
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12_PR {
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12_PR_NOTHING,	/* No components present */
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12_PR_release,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12_PR_setup
} LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12_PR;
typedef enum LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12 {
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_min5	= 0,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_min10	= 1,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_min20	= 2,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_min30	= 3,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_min60	= 4,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_min120	= 5,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_min180	= 6,
	LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12_spare1	= 7
} e_LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup__t350_r12;

/* Forward declarations */
struct LTE_SCG_Configuration_r12;
struct LTE_SL_SyncTxControl_r12;
struct LTE_SL_DiscConfig_r12;
struct LTE_SL_CommConfig_r12;
struct LTE_RRCConnectionReconfiguration_v1310_IEs;

/* LTE_RRCConnectionReconfiguration-v1250-IEs */
typedef struct LTE_RRCConnectionReconfiguration_v1250_IEs {
	struct LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12 {
		LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12_PR present;
		union LTE_RRCConnectionReconfiguration_v1250_IEs__LTE_wlan_OffloadInfo_r12_u {
			NULL_t	 release;
			struct LTE_RRCConnectionReconfiguration_v1250_IEs__wlan_OffloadInfo_r12__setup {
				LTE_WLAN_OffloadConfig_r12_t	 wlan_OffloadConfigDedicated_r12;
				long	*t350_r12;	/* OPTIONAL */
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} setup;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *wlan_OffloadInfo_r12;
	struct LTE_SCG_Configuration_r12	*scg_Configuration_r12;	/* OPTIONAL */
	struct LTE_SL_SyncTxControl_r12	*sl_SyncTxControl_r12;	/* OPTIONAL */
	struct LTE_SL_DiscConfig_r12	*sl_DiscConfig_r12;	/* OPTIONAL */
	struct LTE_SL_CommConfig_r12	*sl_CommConfig_r12;	/* OPTIONAL */
	struct LTE_RRCConnectionReconfiguration_v1310_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RRCConnectionReconfiguration_v1250_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_t350_r12_6;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RRCConnectionReconfiguration_v1250_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_RRCConnectionReconfiguration_v1250_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RRCConnectionReconfiguration_v1250_IEs_1[6];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SCG-Configuration-r12.h"
#include "LTE_SL-SyncTxControl-r12.h"
#include "LTE_SL-DiscConfig-r12.h"
#include "LTE_SL-CommConfig-r12.h"
#include "LTE_RRCConnectionReconfiguration-v1310-IEs.h"

#endif	/* _LTE_RRCConnectionReconfiguration_v1250_IEs_H_ */
#include <asn_internal.h>
