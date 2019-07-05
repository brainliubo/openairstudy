/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_ReportConfigToAddMod_H_
#define	_LTE_ReportConfigToAddMod_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_ReportConfigId.h"
#include "LTE_ReportConfigEUTRA.h"
#include "LTE_ReportConfigInterRAT.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_ReportConfigToAddMod__reportConfig_PR {
	LTE_ReportConfigToAddMod__reportConfig_PR_NOTHING,	/* No components present */
	LTE_ReportConfigToAddMod__reportConfig_PR_reportConfigEUTRA,
	LTE_ReportConfigToAddMod__reportConfig_PR_reportConfigInterRAT
} LTE_ReportConfigToAddMod__reportConfig_PR;

/* LTE_ReportConfigToAddMod */
typedef struct LTE_ReportConfigToAddMod {
	LTE_ReportConfigId_t	 reportConfigId;
	struct LTE_ReportConfigToAddMod__reportConfig {
		LTE_ReportConfigToAddMod__reportConfig_PR present;
		union LTE_ReportConfigToAddMod__LTE_reportConfig_u {
			LTE_ReportConfigEUTRA_t	 reportConfigEUTRA;
			LTE_ReportConfigInterRAT_t	 reportConfigInterRAT;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} reportConfig;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_ReportConfigToAddMod_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_ReportConfigToAddMod;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_ReportConfigToAddMod_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_ReportConfigToAddMod_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_ReportConfigToAddMod_H_ */
#include <asn_internal.h>
