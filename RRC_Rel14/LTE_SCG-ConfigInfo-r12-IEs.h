/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-InterNodeDefinitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SCG_ConfigInfo_r12_IEs_H_
#define	_LTE_SCG_ConfigInfo_r12_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include "LTE_P-Max.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_RadioResourceConfigDedicated;
struct LTE_SCellToAddModList_r10;
struct LTE_MeasGapConfig;
struct LTE_PowerCoordinationInfo_r12;
struct LTE_SCG_ConfigPartSCG_r12;
struct LTE_SCG_ConfigRestrictInfo_r12;
struct LTE_MeasResultServCellListSCG_r12;
struct LTE_DRB_InfoListSCG_r12;
struct LTE_DRB_ToReleaseList;
struct LTE_SCellToAddModListSCG_r12;
struct LTE_SCellToReleaseList_r10;
struct LTE_SCG_ConfigInfo_v1310_IEs;

/* LTE_SCG-ConfigInfo-r12-IEs */
typedef struct LTE_SCG_ConfigInfo_r12_IEs {
	struct LTE_RadioResourceConfigDedicated	*radioResourceConfigDedMCG_r12;	/* OPTIONAL */
	struct LTE_SCellToAddModList_r10	*sCellToAddModListMCG_r12;	/* OPTIONAL */
	struct LTE_MeasGapConfig	*measGapConfig_r12;	/* OPTIONAL */
	struct LTE_PowerCoordinationInfo_r12	*powerCoordinationInfo_r12;	/* OPTIONAL */
	struct LTE_SCG_ConfigPartSCG_r12	*scg_RadioConfig_r12;	/* OPTIONAL */
	OCTET_STRING_t	*eutra_CapabilityInfo_r12;	/* OPTIONAL */
	struct LTE_SCG_ConfigRestrictInfo_r12	*scg_ConfigRestrictInfo_r12;	/* OPTIONAL */
	OCTET_STRING_t	*mbmsInterestIndication_r12;	/* OPTIONAL */
	struct LTE_MeasResultServCellListSCG_r12	*measResultServCellListSCG_r12;	/* OPTIONAL */
	struct LTE_DRB_InfoListSCG_r12	*drb_ToAddModListSCG_r12;	/* OPTIONAL */
	struct LTE_DRB_ToReleaseList	*drb_ToReleaseListSCG_r12;	/* OPTIONAL */
	struct LTE_SCellToAddModListSCG_r12	*sCellToAddModListSCG_r12;	/* OPTIONAL */
	struct LTE_SCellToReleaseList_r10	*sCellToReleaseListSCG_r12;	/* OPTIONAL */
	LTE_P_Max_t	*p_Max_r12;	/* OPTIONAL */
	struct LTE_SCG_ConfigInfo_v1310_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SCG_ConfigInfo_r12_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SCG_ConfigInfo_r12_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_SCG_ConfigInfo_r12_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SCG_ConfigInfo_r12_IEs_1[15];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_RadioResourceConfigDedicated.h"
#include "LTE_SCellToAddModList-r10.h"
#include "LTE_MeasGapConfig.h"
#include "LTE_PowerCoordinationInfo-r12.h"
#include "LTE_SCG-ConfigPartSCG-r12.h"
#include "LTE_SCG-ConfigRestrictInfo-r12.h"
#include "LTE_MeasResultServCellListSCG-r12.h"
#include "LTE_DRB-InfoListSCG-r12.h"
#include "LTE_DRB-ToReleaseList.h"
#include "LTE_SCellToAddModListSCG-r12.h"
#include "LTE_SCellToReleaseList-r10.h"
#include "LTE_SCG-ConfigInfo-v1310-IEs.h"

#endif	/* _LTE_SCG_ConfigInfo_r12_IEs_H_ */
#include <asn_internal.h>
