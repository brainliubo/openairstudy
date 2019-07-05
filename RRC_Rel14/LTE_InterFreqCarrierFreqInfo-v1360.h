/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_InterFreqCarrierFreqInfo_v1360_H_
#define	_LTE_InterFreqCarrierFreqInfo_v1360_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_CellSelectionInfoCE1_v1360;

/* LTE_InterFreqCarrierFreqInfo-v1360 */
typedef struct LTE_InterFreqCarrierFreqInfo_v1360 {
	struct LTE_CellSelectionInfoCE1_v1360	*cellSelectionInfoCE1_v1360;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_InterFreqCarrierFreqInfo_v1360_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_InterFreqCarrierFreqInfo_v1360;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_InterFreqCarrierFreqInfo_v1360_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_InterFreqCarrierFreqInfo_v1360_1[1];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_CellSelectionInfoCE1-v1360.h"

#endif	/* _LTE_InterFreqCarrierFreqInfo_v1360_H_ */
#include <asn_internal.h>
