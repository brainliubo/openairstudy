/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_SRS_ConfigAp_r10_H_
#define	_LTE_SRS_ConfigAp_r10_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_SRS-AntennaPort.h"
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_SRS_ConfigAp_r10__srs_BandwidthAp_r10 {
	LTE_SRS_ConfigAp_r10__srs_BandwidthAp_r10_bw0	= 0,
	LTE_SRS_ConfigAp_r10__srs_BandwidthAp_r10_bw1	= 1,
	LTE_SRS_ConfigAp_r10__srs_BandwidthAp_r10_bw2	= 2,
	LTE_SRS_ConfigAp_r10__srs_BandwidthAp_r10_bw3	= 3
} e_LTE_SRS_ConfigAp_r10__srs_BandwidthAp_r10;
typedef enum LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10 {
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs0	= 0,
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs1	= 1,
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs2	= 2,
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs3	= 3,
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs4	= 4,
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs5	= 5,
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs6	= 6,
	LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10_cs7	= 7
} e_LTE_SRS_ConfigAp_r10__cyclicShiftAp_r10;

/* LTE_SRS-ConfigAp-r10 */
typedef struct LTE_SRS_ConfigAp_r10 {
	LTE_SRS_AntennaPort_t	 srs_AntennaPortAp_r10;
	long	 srs_BandwidthAp_r10;
	long	 freqDomainPositionAp_r10;
	long	 transmissionCombAp_r10;
	long	 cyclicShiftAp_r10;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_SRS_ConfigAp_r10_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_srs_BandwidthAp_r10_3;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_cyclicShiftAp_r10_10;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_SRS_ConfigAp_r10;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_SRS_ConfigAp_r10_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_SRS_ConfigAp_r10_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_SRS_ConfigAp_r10_H_ */
#include <asn_internal.h>
