/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_UL_AM_RLC_NB_r13_H_
#define	_LTE_UL_AM_RLC_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_T-PollRetransmit-NB-r13.h"
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13 {
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t1	= 0,
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t2	= 1,
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t3	= 2,
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t4	= 3,
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t6	= 4,
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t8	= 5,
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t16	= 6,
	LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13_t32	= 7
} e_LTE_UL_AM_RLC_NB_r13__maxRetxThreshold_r13;

/* LTE_UL-AM-RLC-NB-r13 */
typedef struct LTE_UL_AM_RLC_NB_r13 {
	LTE_T_PollRetransmit_NB_r13_t	 t_PollRetransmit_r13;
	long	 maxRetxThreshold_r13;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_UL_AM_RLC_NB_r13_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_maxRetxThreshold_r13_3;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_UL_AM_RLC_NB_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_UL_AM_RLC_NB_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_UL_AM_RLC_NB_r13_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_UL_AM_RLC_NB_r13_H_ */
#include <asn_internal.h>