/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SystemInformationBlockType5_v8h0_IEs_H_
#define	_LTE_SystemInformationBlockType5_v8h0_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_SystemInformationBlockType5_v9e0_IEs;
struct LTE_InterFreqCarrierFreqInfo_v8h0;

/* LTE_SystemInformationBlockType5-v8h0-IEs */
typedef struct LTE_SystemInformationBlockType5_v8h0_IEs {
	struct LTE_SystemInformationBlockType5_v8h0_IEs__interFreqCarrierFreqList_v8h0 {
		A_SEQUENCE_OF(struct LTE_InterFreqCarrierFreqInfo_v8h0) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *interFreqCarrierFreqList_v8h0;
	struct LTE_SystemInformationBlockType5_v9e0_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SystemInformationBlockType5_v8h0_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SystemInformationBlockType5_v8h0_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SystemInformationBlockType5-v9e0-IEs.h"
#include "LTE_InterFreqCarrierFreqInfo-v8h0.h"

#endif	/* _LTE_SystemInformationBlockType5_v8h0_IEs_H_ */
#include <asn_internal.h>
