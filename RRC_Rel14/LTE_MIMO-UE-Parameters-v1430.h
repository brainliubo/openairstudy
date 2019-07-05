/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_MIMO_UE_Parameters_v1430_H_
#define	_LTE_MIMO_UE_Parameters_v1430_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_MIMO_UE_ParametersPerTM_v1430;

/* LTE_MIMO-UE-Parameters-v1430 */
typedef struct LTE_MIMO_UE_Parameters_v1430 {
	struct LTE_MIMO_UE_ParametersPerTM_v1430	*parametersTM9_v1430;	/* OPTIONAL */
	struct LTE_MIMO_UE_ParametersPerTM_v1430	*parametersTM10_v1430;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_MIMO_UE_Parameters_v1430_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_MIMO_UE_Parameters_v1430;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_MIMO_UE_Parameters_v1430_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_MIMO_UE_Parameters_v1430_1[2];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_MIMO-UE-ParametersPerTM-v1430.h"

#endif	/* _LTE_MIMO_UE_Parameters_v1430_H_ */
#include <asn_internal.h>
