/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RadioResourceConfigDedicated_NB_r13_H_
#define	_LTE_RadioResourceConfigDedicated_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_MAC-MainConfig-NB-r13.h"
#include <NULL.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_RadioResourceConfigDedicated_NB_r13__mac_MainConfig_r13_PR {
	LTE_RadioResourceConfigDedicated_NB_r13__mac_MainConfig_r13_PR_NOTHING,	/* No components present */
	LTE_RadioResourceConfigDedicated_NB_r13__mac_MainConfig_r13_PR_explicitValue_r13,
	LTE_RadioResourceConfigDedicated_NB_r13__mac_MainConfig_r13_PR_defaultValue_r13
} LTE_RadioResourceConfigDedicated_NB_r13__mac_MainConfig_r13_PR;

/* Forward declarations */
struct LTE_SRB_ToAddModList_NB_r13;
struct LTE_DRB_ToAddModList_NB_r13;
struct LTE_DRB_ToReleaseList_NB_r13;
struct LTE_PhysicalConfigDedicated_NB_r13;
struct LTE_RLF_TimersAndConstants_NB_r13;

/* LTE_RadioResourceConfigDedicated-NB-r13 */
typedef struct LTE_RadioResourceConfigDedicated_NB_r13 {
	struct LTE_SRB_ToAddModList_NB_r13	*srb_ToAddModList_r13;	/* OPTIONAL */
	struct LTE_DRB_ToAddModList_NB_r13	*drb_ToAddModList_r13;	/* OPTIONAL */
	struct LTE_DRB_ToReleaseList_NB_r13	*drb_ToReleaseList_r13;	/* OPTIONAL */
	struct LTE_RadioResourceConfigDedicated_NB_r13__mac_MainConfig_r13 {
		LTE_RadioResourceConfigDedicated_NB_r13__mac_MainConfig_r13_PR present;
		union LTE_RadioResourceConfigDedicated_NB_r13__LTE_mac_MainConfig_r13_u {
			LTE_MAC_MainConfig_NB_r13_t	 explicitValue_r13;
			NULL_t	 defaultValue_r13;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *mac_MainConfig_r13;
	struct LTE_PhysicalConfigDedicated_NB_r13	*physicalConfigDedicated_r13;	/* OPTIONAL */
	struct LTE_RLF_TimersAndConstants_NB_r13	*rlf_TimersAndConstants_r13;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RadioResourceConfigDedicated_NB_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RadioResourceConfigDedicated_NB_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_RadioResourceConfigDedicated_NB_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RadioResourceConfigDedicated_NB_r13_1[6];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SRB-ToAddModList-NB-r13.h"
#include "LTE_DRB-ToAddModList-NB-r13.h"
#include "LTE_DRB-ToReleaseList-NB-r13.h"
#include "LTE_PhysicalConfigDedicated-NB-r13.h"
#include "LTE_RLF-TimersAndConstants-NB-r13.h"

#endif	/* _LTE_RadioResourceConfigDedicated_NB_r13_H_ */
#include <asn_internal.h>
