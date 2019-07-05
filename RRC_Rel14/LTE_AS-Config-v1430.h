/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-InterNodeDefinitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_AS_Config_v1430_H_
#define	_LTE_AS_Config_v1430_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_SL_V2X_ConfigDedicated_r14;
struct LTE_LWA_Config_r13;
struct LTE_MeasResultListWLAN_r13;

/* LTE_AS-Config-v1430 */
typedef struct LTE_AS_Config_v1430 {
	struct LTE_SL_V2X_ConfigDedicated_r14	*sourceSL_V2X_CommConfig_r14;	/* OPTIONAL */
	struct LTE_LWA_Config_r13	*sourceLWA_Config_r14;	/* OPTIONAL */
	struct LTE_MeasResultListWLAN_r13	*sourceWLAN_MeasResult_r14;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_AS_Config_v1430_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_AS_Config_v1430;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_AS_Config_v1430_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_AS_Config_v1430_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SL-V2X-ConfigDedicated-r14.h"
#include "LTE_LWA-Config-r13.h"
#include "LTE_MeasResultListWLAN-r13.h"

#endif	/* _LTE_AS_Config_v1430_H_ */
#include <asn_internal.h>
