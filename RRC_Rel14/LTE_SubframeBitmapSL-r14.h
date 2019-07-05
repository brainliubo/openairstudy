/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SubframeBitmapSL_r14_H_
#define	_LTE_SubframeBitmapSL_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_SubframeBitmapSL_r14_PR {
	LTE_SubframeBitmapSL_r14_PR_NOTHING,	/* No components present */
	LTE_SubframeBitmapSL_r14_PR_bs10_r14,
	LTE_SubframeBitmapSL_r14_PR_bs16_r14,
	LTE_SubframeBitmapSL_r14_PR_bs20_r14,
	LTE_SubframeBitmapSL_r14_PR_bs30_r14,
	LTE_SubframeBitmapSL_r14_PR_bs40_r14,
	LTE_SubframeBitmapSL_r14_PR_bs50_r14,
	LTE_SubframeBitmapSL_r14_PR_bs60_r14,
	LTE_SubframeBitmapSL_r14_PR_bs100_r14
} LTE_SubframeBitmapSL_r14_PR;

/* LTE_SubframeBitmapSL-r14 */
typedef struct LTE_SubframeBitmapSL_r14 {
	LTE_SubframeBitmapSL_r14_PR present;
	union LTE_SubframeBitmapSL_r14_u {
		BIT_STRING_t	 bs10_r14;
		BIT_STRING_t	 bs16_r14;
		BIT_STRING_t	 bs20_r14;
		BIT_STRING_t	 bs30_r14;
		BIT_STRING_t	 bs40_r14;
		BIT_STRING_t	 bs50_r14;
		BIT_STRING_t	 bs60_r14;
		BIT_STRING_t	 bs100_r14;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SubframeBitmapSL_r14_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SubframeBitmapSL_r14;
extern asn_CHOICE_specifics_t asn_SPC_LTE_SubframeBitmapSL_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SubframeBitmapSL_r14_1[8];
extern asn_per_constraints_t asn_PER_type_LTE_SubframeBitmapSL_r14_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_SubframeBitmapSL_r14_H_ */
#include <asn_internal.h>
