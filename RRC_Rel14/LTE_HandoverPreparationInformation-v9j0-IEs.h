/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-InterNodeDefinitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_HandoverPreparationInformation_v9j0_IEs_H_
#define	_LTE_HandoverPreparationInformation_v9j0_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_HandoverPreparationInformation_v10j0_IEs;

/* LTE_HandoverPreparationInformation-v9j0-IEs */
typedef struct LTE_HandoverPreparationInformation_v9j0_IEs {
	OCTET_STRING_t	*lateNonCriticalExtension;	/* OPTIONAL */
	struct LTE_HandoverPreparationInformation_v10j0_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_HandoverPreparationInformation_v9j0_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_HandoverPreparationInformation_v9j0_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_HandoverPreparationInformation-v10j0-IEs.h"

#endif	/* _LTE_HandoverPreparationInformation_v9j0_IEs_H_ */
#include <asn_internal.h>
