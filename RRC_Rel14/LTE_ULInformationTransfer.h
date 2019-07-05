/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_ULInformationTransfer_H_
#define	_LTE_ULInformationTransfer_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_ULInformationTransfer-r8-IEs.h"
#include <NULL.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_ULInformationTransfer__criticalExtensions_PR {
	LTE_ULInformationTransfer__criticalExtensions_PR_NOTHING,	/* No components present */
	LTE_ULInformationTransfer__criticalExtensions_PR_c1,
	LTE_ULInformationTransfer__criticalExtensions_PR_criticalExtensionsFuture
} LTE_ULInformationTransfer__criticalExtensions_PR;
typedef enum LTE_ULInformationTransfer__criticalExtensions__c1_PR {
	LTE_ULInformationTransfer__criticalExtensions__c1_PR_NOTHING,	/* No components present */
	LTE_ULInformationTransfer__criticalExtensions__c1_PR_ulInformationTransfer_r8,
	LTE_ULInformationTransfer__criticalExtensions__c1_PR_spare3,
	LTE_ULInformationTransfer__criticalExtensions__c1_PR_spare2,
	LTE_ULInformationTransfer__criticalExtensions__c1_PR_spare1
} LTE_ULInformationTransfer__criticalExtensions__c1_PR;

/* LTE_ULInformationTransfer */
typedef struct LTE_ULInformationTransfer {
	struct LTE_ULInformationTransfer__criticalExtensions {
		LTE_ULInformationTransfer__criticalExtensions_PR present;
		union LTE_ULInformationTransfer__LTE_criticalExtensions_u {
			struct LTE_ULInformationTransfer__criticalExtensions__c1 {
				LTE_ULInformationTransfer__criticalExtensions__c1_PR present;
				union LTE_ULInformationTransfer__LTE_criticalExtensions__LTE_c1_u {
					LTE_ULInformationTransfer_r8_IEs_t	 ulInformationTransfer_r8;
					NULL_t	 spare3;
					NULL_t	 spare2;
					NULL_t	 spare1;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} c1;
			struct LTE_ULInformationTransfer__criticalExtensions__criticalExtensionsFuture {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensionsFuture;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} criticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_ULInformationTransfer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_ULInformationTransfer;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_ULInformationTransfer_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_ULInformationTransfer_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_ULInformationTransfer_H_ */
#include <asn_internal.h>
