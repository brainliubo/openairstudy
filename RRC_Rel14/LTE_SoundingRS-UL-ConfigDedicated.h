/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SoundingRS_UL_ConfigDedicated_H_
#define	_LTE_SoundingRS_UL_ConfigDedicated_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_SoundingRS_UL_ConfigDedicated_PR {
	LTE_SoundingRS_UL_ConfigDedicated_PR_NOTHING,	/* No components present */
	LTE_SoundingRS_UL_ConfigDedicated_PR_release,
	LTE_SoundingRS_UL_ConfigDedicated_PR_setup
} LTE_SoundingRS_UL_ConfigDedicated_PR;
typedef enum LTE_SoundingRS_UL_ConfigDedicated__setup__srs_Bandwidth {
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_Bandwidth_bw0	= 0,
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_Bandwidth_bw1	= 1,
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_Bandwidth_bw2	= 2,
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_Bandwidth_bw3	= 3
} e_LTE_SoundingRS_UL_ConfigDedicated__setup__srs_Bandwidth;
typedef enum LTE_SoundingRS_UL_ConfigDedicated__setup__srs_HoppingBandwidth {
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_HoppingBandwidth_hbw0	= 0,
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_HoppingBandwidth_hbw1	= 1,
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_HoppingBandwidth_hbw2	= 2,
	LTE_SoundingRS_UL_ConfigDedicated__setup__srs_HoppingBandwidth_hbw3	= 3
} e_LTE_SoundingRS_UL_ConfigDedicated__setup__srs_HoppingBandwidth;
typedef enum LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift {
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs0	= 0,
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs1	= 1,
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs2	= 2,
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs3	= 3,
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs4	= 4,
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs5	= 5,
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs6	= 6,
	LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift_cs7	= 7
} e_LTE_SoundingRS_UL_ConfigDedicated__setup__cyclicShift;

/* LTE_SoundingRS-UL-ConfigDedicated */
typedef struct LTE_SoundingRS_UL_ConfigDedicated {
	LTE_SoundingRS_UL_ConfigDedicated_PR present;
	union LTE_SoundingRS_UL_ConfigDedicated_u {
		NULL_t	 release;
		struct LTE_SoundingRS_UL_ConfigDedicated__setup {
			long	 srs_Bandwidth;
			long	 srs_HoppingBandwidth;
			long	 freqDomainPosition;
			BOOLEAN_t	 duration;
			long	 srs_ConfigIndex;
			long	 transmissionComb;
			long	 cyclicShift;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} setup;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SoundingRS_UL_ConfigDedicated_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_srs_Bandwidth_4;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_srs_HoppingBandwidth_9;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_cyclicShift_18;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SoundingRS_UL_ConfigDedicated;
extern asn_CHOICE_specifics_t asn_SPC_LTE_SoundingRS_UL_ConfigDedicated_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SoundingRS_UL_ConfigDedicated_1[2];
extern asn_per_constraints_t asn_PER_type_LTE_SoundingRS_UL_ConfigDedicated_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_SoundingRS_UL_ConfigDedicated_H_ */
#include <asn_internal.h>
