/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_CQI_ReportPeriodic_r10_H_
#define	_LTE_CQI_ReportPeriodic_r10_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <NativeInteger.h>
#include <BOOLEAN.h>
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_CQI_ReportPeriodic_r10_PR {
	LTE_CQI_ReportPeriodic_r10_PR_NOTHING,	/* No components present */
	LTE_CQI_ReportPeriodic_r10_PR_release,
	LTE_CQI_ReportPeriodic_r10_PR_setup
} LTE_CQI_ReportPeriodic_r10_PR;
typedef enum LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10_PR {
	LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10_PR_NOTHING,	/* No components present */
	LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10_PR_widebandCQI_r10,
	LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10_PR_subbandCQI_r10
} LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10_PR;
typedef enum LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__widebandCQI_r10__csi_ReportMode_r10 {
	LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__widebandCQI_r10__csi_ReportMode_r10_submode1	= 0,
	LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__widebandCQI_r10__csi_ReportMode_r10_submode2	= 1
} e_LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__widebandCQI_r10__csi_ReportMode_r10;
typedef enum LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__subbandCQI_r10__periodicityFactor_r10 {
	LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__subbandCQI_r10__periodicityFactor_r10_n2	= 0,
	LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__subbandCQI_r10__periodicityFactor_r10_n4	= 1
} e_LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__subbandCQI_r10__periodicityFactor_r10;
typedef enum LTE_CQI_ReportPeriodic_r10__setup__cqi_Mask_r9 {
	LTE_CQI_ReportPeriodic_r10__setup__cqi_Mask_r9_setup	= 0
} e_LTE_CQI_ReportPeriodic_r10__setup__cqi_Mask_r9;
typedef enum LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10_PR {
	LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10_PR_NOTHING,	/* No components present */
	LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10_PR_release,
	LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10_PR_setup
} LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10_PR;

/* LTE_CQI-ReportPeriodic-r10 */
typedef struct LTE_CQI_ReportPeriodic_r10 {
	LTE_CQI_ReportPeriodic_r10_PR present;
	union LTE_CQI_ReportPeriodic_r10_u {
		NULL_t	 release;
		struct LTE_CQI_ReportPeriodic_r10__setup {
			long	 cqi_PUCCH_ResourceIndex_r10;
			long	*cqi_PUCCH_ResourceIndexP1_r10;	/* OPTIONAL */
			long	 cqi_pmi_ConfigIndex;
			struct LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10 {
				LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10_PR present;
				union LTE_CQI_ReportPeriodic_r10__LTE_setup__LTE_cqi_FormatIndicatorPeriodic_r10_u {
					struct LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__widebandCQI_r10 {
						long	*csi_ReportMode_r10;	/* OPTIONAL */
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} widebandCQI_r10;
					struct LTE_CQI_ReportPeriodic_r10__setup__cqi_FormatIndicatorPeriodic_r10__subbandCQI_r10 {
						long	 k;
						long	 periodicityFactor_r10;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} subbandCQI_r10;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} cqi_FormatIndicatorPeriodic_r10;
			long	*ri_ConfigIndex;	/* OPTIONAL */
			BOOLEAN_t	 simultaneousAckNackAndCQI;
			long	*cqi_Mask_r9;	/* OPTIONAL */
			struct LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10 {
				LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10_PR present;
				union LTE_CQI_ReportPeriodic_r10__LTE_setup__LTE_csi_ConfigIndex_r10_u {
					NULL_t	 release;
					struct LTE_CQI_ReportPeriodic_r10__setup__csi_ConfigIndex_r10__setup {
						long	 cqi_pmi_ConfigIndex2_r10;
						long	*ri_ConfigIndex2_r10;	/* OPTIONAL */
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} setup;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *csi_ConfigIndex_r10;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} setup;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_CQI_ReportPeriodic_r10_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_csi_ReportMode_r10_9;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_periodicityFactor_r10_14;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_cqi_Mask_r9_19;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_CQI_ReportPeriodic_r10;
extern asn_CHOICE_specifics_t asn_SPC_LTE_CQI_ReportPeriodic_r10_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_CQI_ReportPeriodic_r10_1[2];
extern asn_per_constraints_t asn_PER_type_LTE_CQI_ReportPeriodic_r10_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_CQI_ReportPeriodic_r10_H_ */
#include <asn_internal.h>
