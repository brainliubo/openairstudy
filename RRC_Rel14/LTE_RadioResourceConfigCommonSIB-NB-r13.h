/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RadioResourceConfigCommonSIB_NB_r13_H_
#define	_LTE_RadioResourceConfigCommonSIB_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_RACH-ConfigCommon-NB-r13.h"
#include "LTE_BCCH-Config-NB-r13.h"
#include "LTE_PCCH-Config-NB-r13.h"
#include "LTE_NPRACH-ConfigSIB-NB-r13.h"
#include "LTE_NPDSCH-ConfigCommon-NB-r13.h"
#include "LTE_NPUSCH-ConfigCommon-NB-r13.h"
#include "LTE_UplinkPowerControlCommon-NB-r13.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_DL_GapConfig_NB_r13;
struct LTE_NPRACH_ConfigSIB_NB_v1330;
struct LTE_NPRACH_ConfigSIB_NB_v1450;

/* LTE_RadioResourceConfigCommonSIB-NB-r13 */
typedef struct LTE_RadioResourceConfigCommonSIB_NB_r13 {
	LTE_RACH_ConfigCommon_NB_r13_t	 rach_ConfigCommon_r13;
	LTE_BCCH_Config_NB_r13_t	 bcch_Config_r13;
	LTE_PCCH_Config_NB_r13_t	 pcch_Config_r13;
	LTE_NPRACH_ConfigSIB_NB_r13_t	 nprach_Config_r13;
	LTE_NPDSCH_ConfigCommon_NB_r13_t	 npdsch_ConfigCommon_r13;
	LTE_NPUSCH_ConfigCommon_NB_r13_t	 npusch_ConfigCommon_r13;
	struct LTE_DL_GapConfig_NB_r13	*dl_Gap_r13;	/* OPTIONAL */
	LTE_UplinkPowerControlCommon_NB_r13_t	 uplinkPowerControlCommon_r13;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct LTE_RadioResourceConfigCommonSIB_NB_r13__ext1 {
		struct LTE_NPRACH_ConfigSIB_NB_v1330	*nprach_Config_v1330;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext1;
	struct LTE_RadioResourceConfigCommonSIB_NB_r13__ext2 {
		struct LTE_NPRACH_ConfigSIB_NB_v1450	*nprach_Config_v1450;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext2;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RadioResourceConfigCommonSIB_NB_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RadioResourceConfigCommonSIB_NB_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_RadioResourceConfigCommonSIB_NB_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RadioResourceConfigCommonSIB_NB_r13_1[10];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_DL-GapConfig-NB-r13.h"
#include "LTE_NPRACH-ConfigSIB-NB-v1330.h"
#include "LTE_NPRACH-ConfigSIB-NB-v1450.h"

#endif	/* _LTE_RadioResourceConfigCommonSIB_NB_r13_H_ */
#include <asn_internal.h>
