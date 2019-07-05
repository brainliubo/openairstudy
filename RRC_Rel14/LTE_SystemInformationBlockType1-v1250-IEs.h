/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SystemInformationBlockType1_v1250_IEs_H_
#define	_LTE_SystemInformationBlockType1_v1250_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_SystemInformationBlockType1_v1250_IEs__cellAccessRelatedInfo_v1250__category0Allowed_r12 {
	LTE_SystemInformationBlockType1_v1250_IEs__cellAccessRelatedInfo_v1250__category0Allowed_r12_true	= 0
} e_LTE_SystemInformationBlockType1_v1250_IEs__cellAccessRelatedInfo_v1250__category0Allowed_r12;
typedef enum LTE_SystemInformationBlockType1_v1250_IEs__freqBandIndicatorPriority_r12 {
	LTE_SystemInformationBlockType1_v1250_IEs__freqBandIndicatorPriority_r12_true	= 0
} e_LTE_SystemInformationBlockType1_v1250_IEs__freqBandIndicatorPriority_r12;

/* Forward declarations */
struct LTE_CellSelectionInfo_v1250;
struct LTE_SystemInformationBlockType1_v1310_IEs;

/* LTE_SystemInformationBlockType1-v1250-IEs */
typedef struct LTE_SystemInformationBlockType1_v1250_IEs {
	struct LTE_SystemInformationBlockType1_v1250_IEs__cellAccessRelatedInfo_v1250 {
		long	*category0Allowed_r12;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} cellAccessRelatedInfo_v1250;
	struct LTE_CellSelectionInfo_v1250	*cellSelectionInfo_v1250;	/* OPTIONAL */
	long	*freqBandIndicatorPriority_r12;	/* OPTIONAL */
	struct LTE_SystemInformationBlockType1_v1310_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SystemInformationBlockType1_v1250_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_category0Allowed_r12_3;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_freqBandIndicatorPriority_r12_6;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SystemInformationBlockType1_v1250_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_SystemInformationBlockType1_v1250_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SystemInformationBlockType1_v1250_IEs_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_CellSelectionInfo-v1250.h"
#include "LTE_SystemInformationBlockType1-v1310-IEs.h"

#endif	/* _LTE_SystemInformationBlockType1_v1250_IEs_H_ */
#include <asn_internal.h>
