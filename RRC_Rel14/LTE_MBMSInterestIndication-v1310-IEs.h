/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_MBMSInterestIndication_v1310_IEs_H_
#define	_LTE_MBMSInterestIndication_v1310_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_MBMS_ServiceList_r13;

/* LTE_MBMSInterestIndication-v1310-IEs */
typedef struct LTE_MBMSInterestIndication_v1310_IEs {
	struct LTE_MBMS_ServiceList_r13	*mbms_Services_r13;	/* OPTIONAL */
	struct LTE_MBMSInterestIndication_v1310_IEs__nonCriticalExtension {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtension;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_MBMSInterestIndication_v1310_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_MBMSInterestIndication_v1310_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_MBMSInterestIndication_v1310_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_MBMSInterestIndication_v1310_IEs_1[2];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_MBMS-ServiceList-r13.h"

#endif	/* _LTE_MBMSInterestIndication_v1310_IEs_H_ */
#include <asn_internal.h>
