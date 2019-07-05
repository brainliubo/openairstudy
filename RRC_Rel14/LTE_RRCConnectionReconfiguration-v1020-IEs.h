/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RRCConnectionReconfiguration_v1020_IEs_H_
#define	_LTE_RRCConnectionReconfiguration_v1020_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_SCellToReleaseList_r10;
struct LTE_SCellToAddModList_r10;
struct LTE_RRCConnectionReconfiguration_v1130_IEs;

/* LTE_RRCConnectionReconfiguration-v1020-IEs */
typedef struct LTE_RRCConnectionReconfiguration_v1020_IEs {
	struct LTE_SCellToReleaseList_r10	*sCellToReleaseList_r10;	/* OPTIONAL */
	struct LTE_SCellToAddModList_r10	*sCellToAddModList_r10;	/* OPTIONAL */
	struct LTE_RRCConnectionReconfiguration_v1130_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RRCConnectionReconfiguration_v1020_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RRCConnectionReconfiguration_v1020_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_RRCConnectionReconfiguration_v1020_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RRCConnectionReconfiguration_v1020_IEs_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_SCellToReleaseList-r10.h"
#include "LTE_SCellToAddModList-r10.h"
#include "LTE_RRCConnectionReconfiguration-v1130-IEs.h"

#endif	/* _LTE_RRCConnectionReconfiguration_v1020_IEs_H_ */
#include <asn_internal.h>
