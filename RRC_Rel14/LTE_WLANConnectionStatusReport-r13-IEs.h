/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_WLANConnectionStatusReport_r13_IEs_H_
#define	_LTE_WLANConnectionStatusReport_r13_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_WLAN-Status-r13.h"
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_WLANConnectionStatusReport_v1430_IEs;

/* LTE_WLANConnectionStatusReport-r13-IEs */
typedef struct LTE_WLANConnectionStatusReport_r13_IEs {
	LTE_WLAN_Status_r13_t	 wlan_Status_r13;
	OCTET_STRING_t	*lateNonCriticalExtension;	/* OPTIONAL */
	struct LTE_WLANConnectionStatusReport_v1430_IEs	*nonCriticalExtension;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_WLANConnectionStatusReport_r13_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_WLANConnectionStatusReport_r13_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_WLANConnectionStatusReport_r13_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_WLANConnectionStatusReport_r13_IEs_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_WLANConnectionStatusReport-v1430-IEs.h"

#endif	/* _LTE_WLANConnectionStatusReport_r13_IEs_H_ */
#include <asn_internal.h>