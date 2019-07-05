/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_CarrierFreqsGERAN_H_
#define	_LTE_CarrierFreqsGERAN_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_ARFCN-ValueGERAN.h"
#include "LTE_BandIndicatorGERAN.h"
#include "LTE_ExplicitListOfARFCNs.h"
#include <OCTET_STRING.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_CarrierFreqsGERAN__followingARFCNs_PR {
	LTE_CarrierFreqsGERAN__followingARFCNs_PR_NOTHING,	/* No components present */
	LTE_CarrierFreqsGERAN__followingARFCNs_PR_explicitListOfARFCNs,
	LTE_CarrierFreqsGERAN__followingARFCNs_PR_equallySpacedARFCNs,
	LTE_CarrierFreqsGERAN__followingARFCNs_PR_variableBitMapOfARFCNs
} LTE_CarrierFreqsGERAN__followingARFCNs_PR;

/* LTE_CarrierFreqsGERAN */
typedef struct LTE_CarrierFreqsGERAN {
	LTE_ARFCN_ValueGERAN_t	 startingARFCN;
	LTE_BandIndicatorGERAN_t	 bandIndicator;
	struct LTE_CarrierFreqsGERAN__followingARFCNs {
		LTE_CarrierFreqsGERAN__followingARFCNs_PR present;
		union LTE_CarrierFreqsGERAN__LTE_followingARFCNs_u {
			LTE_ExplicitListOfARFCNs_t	 explicitListOfARFCNs;
			struct LTE_CarrierFreqsGERAN__followingARFCNs__equallySpacedARFCNs {
				long	 arfcn_Spacing;
				long	 numberOfFollowingARFCNs;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} equallySpacedARFCNs;
			OCTET_STRING_t	 variableBitMapOfARFCNs;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} followingARFCNs;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_CarrierFreqsGERAN_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_CarrierFreqsGERAN;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_CarrierFreqsGERAN_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_CarrierFreqsGERAN_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_CarrierFreqsGERAN_H_ */
#include <asn_internal.h>
