/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SL_Parameters_v1310_H_
#define	_LTE_SL_Parameters_v1310_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_SL_Parameters_v1310__discSysInfoReporting_r13 {
	LTE_SL_Parameters_v1310__discSysInfoReporting_r13_supported	= 0
} e_LTE_SL_Parameters_v1310__discSysInfoReporting_r13;
typedef enum LTE_SL_Parameters_v1310__commMultipleTx_r13 {
	LTE_SL_Parameters_v1310__commMultipleTx_r13_supported	= 0
} e_LTE_SL_Parameters_v1310__commMultipleTx_r13;
typedef enum LTE_SL_Parameters_v1310__discInterFreqTx_r13 {
	LTE_SL_Parameters_v1310__discInterFreqTx_r13_supported	= 0
} e_LTE_SL_Parameters_v1310__discInterFreqTx_r13;
typedef enum LTE_SL_Parameters_v1310__discPeriodicSLSS_r13 {
	LTE_SL_Parameters_v1310__discPeriodicSLSS_r13_supported	= 0
} e_LTE_SL_Parameters_v1310__discPeriodicSLSS_r13;

/* LTE_SL-Parameters-v1310 */
typedef struct LTE_SL_Parameters_v1310 {
	long	*discSysInfoReporting_r13;	/* OPTIONAL */
	long	*commMultipleTx_r13;	/* OPTIONAL */
	long	*discInterFreqTx_r13;	/* OPTIONAL */
	long	*discPeriodicSLSS_r13;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SL_Parameters_v1310_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_discSysInfoReporting_r13_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_commMultipleTx_r13_4;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_discInterFreqTx_r13_6;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_discPeriodicSLSS_r13_8;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SL_Parameters_v1310;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_SL_Parameters_v1310_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SL_Parameters_v1310_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_SL_Parameters_v1310_H_ */
#include <asn_internal.h>
