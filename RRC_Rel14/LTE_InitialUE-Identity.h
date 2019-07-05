/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_InitialUE_Identity_H_
#define	_LTE_InitialUE_Identity_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_S-TMSI.h"
#include <BIT_STRING.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_InitialUE_Identity_PR {
	LTE_InitialUE_Identity_PR_NOTHING,	/* No components present */
	LTE_InitialUE_Identity_PR_s_TMSI,
	LTE_InitialUE_Identity_PR_randomValue
} LTE_InitialUE_Identity_PR;

/* LTE_InitialUE-Identity */
typedef struct LTE_InitialUE_Identity {
	LTE_InitialUE_Identity_PR present;
	union LTE_InitialUE_Identity_u {
		LTE_S_TMSI_t	 s_TMSI;
		BIT_STRING_t	 randomValue;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_InitialUE_Identity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_InitialUE_Identity;
extern asn_CHOICE_specifics_t asn_SPC_LTE_InitialUE_Identity_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_InitialUE_Identity_1[2];
extern asn_per_constraints_t asn_PER_type_LTE_InitialUE_Identity_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_InitialUE_Identity_H_ */
#include <asn_internal.h>
