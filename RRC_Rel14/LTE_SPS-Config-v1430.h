/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SPS_Config_v1430_H_
#define	_LTE_SPS_Config_v1430_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_C-RNTI.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_SPS_ConfigUL_ToAddModList_r14;
struct LTE_SPS_ConfigUL_ToReleaseList_r14;
struct LTE_SPS_ConfigSL_ToAddModList_r14;
struct LTE_SPS_ConfigSL_ToReleaseList_r14;

/* LTE_SPS-Config-v1430 */
typedef struct LTE_SPS_Config_v1430 {
	LTE_C_RNTI_t	*ul_SPS_V_RNTI_r14;	/* OPTIONAL */
	LTE_C_RNTI_t	*sl_SPS_V_RNTI_r14;	/* OPTIONAL */
	struct LTE_SPS_ConfigUL_ToAddModList_r14	*sps_ConfigUL_ToAddModList_r14;	/* OPTIONAL */
	struct LTE_SPS_ConfigUL_ToReleaseList_r14	*sps_ConfigUL_ToReleaseList_r14;	/* OPTIONAL */
	struct LTE_SPS_ConfigSL_ToAddModList_r14	*sps_ConfigSL_ToAddModList_r14;	/* OPTIONAL */
	struct LTE_SPS_ConfigSL_ToReleaseList_r14	*sps_ConfigSL_ToReleaseList_r14;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SPS_Config_v1430_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SPS_Config_v1430;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_SPS_Config_v1430_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SPS_Config_v1430_1[6];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SPS-ConfigUL-ToAddModList-r14.h"
#include "LTE_SPS-ConfigUL-ToReleaseList-r14.h"
#include "LTE_SPS-ConfigSL-ToAddModList-r14.h"
#include "LTE_SPS-ConfigSL-ToReleaseList-r14.h"

#endif	/* _LTE_SPS_Config_v1430_H_ */
#include <asn_internal.h>