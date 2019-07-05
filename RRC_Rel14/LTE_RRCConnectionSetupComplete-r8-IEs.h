/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RRCConnectionSetupComplete_r8_IEs_H_
#define	_LTE_RRCConnectionSetupComplete_r8_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "LTE_DedicatedInfoNAS.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_RegisteredMME;
struct LTE_RRCConnectionSetupComplete_v8a0_IEs;

/* LTE_RRCConnectionSetupComplete-r8-IEs */
typedef struct LTE_RRCConnectionSetupComplete_r8_IEs {
	long	 selectedPLMN_Identity;
	struct LTE_RegisteredMME	*registeredMME;	/* OPTIONAL */
	LTE_DedicatedInfoNAS_t	 dedicatedInfoNAS;
	struct LTE_RRCConnectionSetupComplete_v8a0_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RRCConnectionSetupComplete_r8_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RRCConnectionSetupComplete_r8_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_RRCConnectionSetupComplete_r8_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RRCConnectionSetupComplete_r8_IEs_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_RegisteredMME.h"
#include "LTE_RRCConnectionSetupComplete-v8a0-IEs.h"

#endif	/* _LTE_RRCConnectionSetupComplete_r8_IEs_H_ */
#include <asn_internal.h>
