/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_MeasGapSharingConfig_r14_H_
#define	_LTE_MeasGapSharingConfig_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_MeasGapSharingConfig_r14_PR {
	LTE_MeasGapSharingConfig_r14_PR_NOTHING,	/* No components present */
	LTE_MeasGapSharingConfig_r14_PR_release,
	LTE_MeasGapSharingConfig_r14_PR_setup
} LTE_MeasGapSharingConfig_r14_PR;
typedef enum LTE_MeasGapSharingConfig_r14__setup__measGapSharingScheme_r14 {
	LTE_MeasGapSharingConfig_r14__setup__measGapSharingScheme_r14_scheme00	= 0,
	LTE_MeasGapSharingConfig_r14__setup__measGapSharingScheme_r14_scheme01	= 1,
	LTE_MeasGapSharingConfig_r14__setup__measGapSharingScheme_r14_scheme10	= 2,
	LTE_MeasGapSharingConfig_r14__setup__measGapSharingScheme_r14_scheme11	= 3
} e_LTE_MeasGapSharingConfig_r14__setup__measGapSharingScheme_r14;

/* LTE_MeasGapSharingConfig-r14 */
typedef struct LTE_MeasGapSharingConfig_r14 {
	LTE_MeasGapSharingConfig_r14_PR present;
	union LTE_MeasGapSharingConfig_r14_u {
		NULL_t	 release;
		struct LTE_MeasGapSharingConfig_r14__setup {
			long	 measGapSharingScheme_r14;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} setup;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_MeasGapSharingConfig_r14_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_measGapSharingScheme_r14_4;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_MeasGapSharingConfig_r14;
extern asn_CHOICE_specifics_t asn_SPC_LTE_MeasGapSharingConfig_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_MeasGapSharingConfig_r14_1[2];
extern asn_per_constraints_t asn_PER_type_LTE_MeasGapSharingConfig_r14_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_MeasGapSharingConfig_r14_H_ */
#include <asn_internal.h>
