/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RF_Parameters_v1270_H_
#define	_LTE_RF_Parameters_v1270_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_SupportedBandCombination_v1270;
struct LTE_SupportedBandCombinationAdd_v1270;

/* LTE_RF-Parameters-v1270 */
typedef struct LTE_RF_Parameters_v1270 {
	struct LTE_SupportedBandCombination_v1270	*supportedBandCombination_v1270;	/* OPTIONAL */
	struct LTE_SupportedBandCombinationAdd_v1270	*supportedBandCombinationAdd_v1270;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RF_Parameters_v1270_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RF_Parameters_v1270;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_RF_Parameters_v1270_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RF_Parameters_v1270_1[2];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SupportedBandCombination-v1270.h"
#include "LTE_SupportedBandCombinationAdd-v1270.h"

#endif	/* _LTE_RF_Parameters_v1270_H_ */
#include <asn_internal.h>
