/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_MUST_Parameters_r14_H_
#define	_LTE_MUST_Parameters_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_MUST_Parameters_r14__must_TM234_UpTo2Tx_r14 {
	LTE_MUST_Parameters_r14__must_TM234_UpTo2Tx_r14_supported	= 0
} e_LTE_MUST_Parameters_r14__must_TM234_UpTo2Tx_r14;
typedef enum LTE_MUST_Parameters_r14__must_TM89_UpToOneInterferingLayer_r14 {
	LTE_MUST_Parameters_r14__must_TM89_UpToOneInterferingLayer_r14_supported	= 0
} e_LTE_MUST_Parameters_r14__must_TM89_UpToOneInterferingLayer_r14;
typedef enum LTE_MUST_Parameters_r14__must_TM10_UpToOneInterferingLayer_r14 {
	LTE_MUST_Parameters_r14__must_TM10_UpToOneInterferingLayer_r14_supported	= 0
} e_LTE_MUST_Parameters_r14__must_TM10_UpToOneInterferingLayer_r14;
typedef enum LTE_MUST_Parameters_r14__must_TM89_UpToThreeInterferingLayers_r14 {
	LTE_MUST_Parameters_r14__must_TM89_UpToThreeInterferingLayers_r14_supported	= 0
} e_LTE_MUST_Parameters_r14__must_TM89_UpToThreeInterferingLayers_r14;
typedef enum LTE_MUST_Parameters_r14__must_TM10_UpToThreeInterferingLayers_r14 {
	LTE_MUST_Parameters_r14__must_TM10_UpToThreeInterferingLayers_r14_supported	= 0
} e_LTE_MUST_Parameters_r14__must_TM10_UpToThreeInterferingLayers_r14;

/* LTE_MUST-Parameters-r14 */
typedef struct LTE_MUST_Parameters_r14 {
	long	*must_TM234_UpTo2Tx_r14;	/* OPTIONAL */
	long	*must_TM89_UpToOneInterferingLayer_r14;	/* OPTIONAL */
	long	*must_TM10_UpToOneInterferingLayer_r14;	/* OPTIONAL */
	long	*must_TM89_UpToThreeInterferingLayers_r14;	/* OPTIONAL */
	long	*must_TM10_UpToThreeInterferingLayers_r14;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_MUST_Parameters_r14_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_must_TM234_UpTo2Tx_r14_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_must_TM89_UpToOneInterferingLayer_r14_4;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_must_TM10_UpToOneInterferingLayer_r14_6;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_must_TM89_UpToThreeInterferingLayers_r14_8;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_must_TM10_UpToThreeInterferingLayers_r14_10;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_MUST_Parameters_r14;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_MUST_Parameters_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_MUST_Parameters_r14_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_MUST_Parameters_r14_H_ */
#include <asn_internal.h>
