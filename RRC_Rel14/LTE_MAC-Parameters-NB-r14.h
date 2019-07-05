/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_MAC_Parameters_NB_r14_H_
#define	_LTE_MAC_Parameters_NB_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_MAC_Parameters_NB_r14__dataInactMon_r14 {
	LTE_MAC_Parameters_NB_r14__dataInactMon_r14_supported	= 0
} e_LTE_MAC_Parameters_NB_r14__dataInactMon_r14;
typedef enum LTE_MAC_Parameters_NB_r14__rai_Support_r14 {
	LTE_MAC_Parameters_NB_r14__rai_Support_r14_supported	= 0
} e_LTE_MAC_Parameters_NB_r14__rai_Support_r14;

/* LTE_MAC-Parameters-NB-r14 */
typedef struct LTE_MAC_Parameters_NB_r14 {
	long	*dataInactMon_r14;	/* OPTIONAL */
	long	*rai_Support_r14;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_MAC_Parameters_NB_r14_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_dataInactMon_r14_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_rai_Support_r14_4;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_MAC_Parameters_NB_r14;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_MAC_Parameters_NB_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_MAC_Parameters_NB_r14_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_MAC_Parameters_NB_r14_H_ */
#include <asn_internal.h>
