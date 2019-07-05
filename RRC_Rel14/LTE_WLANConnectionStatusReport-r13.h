/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_WLANConnectionStatusReport_r13_H_
#define	_LTE_WLANConnectionStatusReport_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_WLANConnectionStatusReport-r13-IEs.h"
#include <NULL.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_WLANConnectionStatusReport_r13__criticalExtensions_PR {
	LTE_WLANConnectionStatusReport_r13__criticalExtensions_PR_NOTHING,	/* No components present */
	LTE_WLANConnectionStatusReport_r13__criticalExtensions_PR_c1,
	LTE_WLANConnectionStatusReport_r13__criticalExtensions_PR_criticalExtensionsFuture
} LTE_WLANConnectionStatusReport_r13__criticalExtensions_PR;
typedef enum LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR {
	LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR_NOTHING,	/* No components present */
	LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR_wlanConnectionStatusReport_r13,
	LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR_spare3,
	LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR_spare2,
	LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR_spare1
} LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR;

/* LTE_WLANConnectionStatusReport-r13 */
typedef struct LTE_WLANConnectionStatusReport_r13 {
	struct LTE_WLANConnectionStatusReport_r13__criticalExtensions {
		LTE_WLANConnectionStatusReport_r13__criticalExtensions_PR present;
		union LTE_WLANConnectionStatusReport_r13__LTE_criticalExtensions_u {
			struct LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1 {
				LTE_WLANConnectionStatusReport_r13__criticalExtensions__c1_PR present;
				union LTE_WLANConnectionStatusReport_r13__LTE_criticalExtensions__LTE_c1_u {
					LTE_WLANConnectionStatusReport_r13_IEs_t	 wlanConnectionStatusReport_r13;
					NULL_t	 spare3;
					NULL_t	 spare2;
					NULL_t	 spare1;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} c1;
			struct LTE_WLANConnectionStatusReport_r13__criticalExtensions__criticalExtensionsFuture {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensionsFuture;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} criticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_WLANConnectionStatusReport_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_WLANConnectionStatusReport_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_WLANConnectionStatusReport_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_WLANConnectionStatusReport_r13_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_WLANConnectionStatusReport_r13_H_ */
#include <asn_internal.h>
