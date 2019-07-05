/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_AntennaInfoDedicated_v920_H_
#define	_LTE_AntennaInfoDedicated_v920_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_AntennaInfoDedicated_v920__codebookSubsetRestriction_v920_PR {
	LTE_AntennaInfoDedicated_v920__codebookSubsetRestriction_v920_PR_NOTHING,	/* No components present */
	LTE_AntennaInfoDedicated_v920__codebookSubsetRestriction_v920_PR_n2TxAntenna_tm8_r9,
	LTE_AntennaInfoDedicated_v920__codebookSubsetRestriction_v920_PR_n4TxAntenna_tm8_r9
} LTE_AntennaInfoDedicated_v920__codebookSubsetRestriction_v920_PR;

/* LTE_AntennaInfoDedicated-v920 */
typedef struct LTE_AntennaInfoDedicated_v920 {
	struct LTE_AntennaInfoDedicated_v920__codebookSubsetRestriction_v920 {
		LTE_AntennaInfoDedicated_v920__codebookSubsetRestriction_v920_PR present;
		union LTE_AntennaInfoDedicated_v920__LTE_codebookSubsetRestriction_v920_u {
			BIT_STRING_t	 n2TxAntenna_tm8_r9;
			BIT_STRING_t	 n4TxAntenna_tm8_r9;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *codebookSubsetRestriction_v920;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_AntennaInfoDedicated_v920_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_AntennaInfoDedicated_v920;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_AntennaInfoDedicated_v920_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_AntennaInfoDedicated_v920_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_AntennaInfoDedicated_v920_H_ */
#include <asn_internal.h>
