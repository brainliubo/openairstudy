/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060_H_
#define	_LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_PhyLayerParameters_v1020;
struct LTE_IRAT_ParametersCDMA2000_1XRTT_v1020;
struct LTE_IRAT_ParametersUTRA_TDD_v1020;
struct LTE_OTDOA_PositioningCapabilities_r10;

/* LTE_UE-EUTRA-CapabilityAddXDD-Mode-v1060 */
typedef struct LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060 {
	struct LTE_PhyLayerParameters_v1020	*phyLayerParameters_v1060;	/* OPTIONAL */
	BIT_STRING_t	*featureGroupIndRel10_v1060;	/* OPTIONAL */
	struct LTE_IRAT_ParametersCDMA2000_1XRTT_v1020	*interRAT_ParametersCDMA2000_v1060;	/* OPTIONAL */
	struct LTE_IRAT_ParametersUTRA_TDD_v1020	*interRAT_ParametersUTRA_TDD_v1060;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060__ext1 {
		struct LTE_OTDOA_PositioningCapabilities_r10	*otdoa_PositioningCapabilities_r10;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext1;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060_1[5];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_PhyLayerParameters-v1020.h"
#include "LTE_IRAT-ParametersCDMA2000-1XRTT-v1020.h"
#include "LTE_IRAT-ParametersUTRA-TDD-v1020.h"
#include "LTE_OTDOA-PositioningCapabilities-r10.h"

#endif	/* _LTE_UE_EUTRA_CapabilityAddXDD_Mode_v1060_H_ */
#include <asn_internal.h>
