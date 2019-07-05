/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470_H_
#define	_LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14 {
	LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14_n8	= 0,
	LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14_n12	= 1,
	LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14_n16	= 2,
	LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14_n20	= 3,
	LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14_n24	= 4,
	LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14_n28	= 5
} e_LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470__csi_ReportingAdvancedMaxPorts_r14;

/* LTE_MIMO-CA-ParametersPerBoBCPerTM-v1470 */
typedef struct LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470 {
	long	*csi_ReportingAdvancedMaxPorts_r14;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_csi_ReportingAdvancedMaxPorts_r14_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_MIMO_CA_ParametersPerBoBCPerTM_v1470_H_ */
#include <asn_internal.h>
