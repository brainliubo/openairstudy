/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_NPRACH_Parameters_NB_r14_H_
#define	_LTE_NPRACH_Parameters_NB_r14_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms40	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms80	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms160	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms240	= 3,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms320	= 4,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms640	= 5,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms1280	= 6,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14_ms2560	= 7
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_Periodicity_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms8	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms16	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms32	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms64	= 3,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms128	= 4,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms256	= 5,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms512	= 6,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14_ms1024	= 7
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_StartTime_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_n0	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_n12	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_n24	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_n36	= 3,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_n2	= 4,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_n18	= 5,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_n34	= 6,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14_spare1	= 7
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierOffset_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumSubcarriers_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumSubcarriers_r14_n12	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumSubcarriers_r14_n24	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumSubcarriers_r14_n36	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumSubcarriers_r14_n48	= 3
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumSubcarriers_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierMSG3_RangeStart_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierMSG3_RangeStart_r14_zero	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierMSG3_RangeStart_r14_oneThird	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierMSG3_RangeStart_r14_twoThird	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierMSG3_RangeStart_r14_one	= 3
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_SubcarrierMSG3_RangeStart_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r1	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r2	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r4	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r8	= 3,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r16	= 4,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r32	= 5,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r64	= 6,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r128	= 7,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r256	= 8,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r512	= 9,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r1024	= 10,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_r2048	= 11,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_spare4	= 12,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_spare3	= 13,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_spare2	= 14,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14_spare1	= 15
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_NumRepetitions_RA_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v1dot5	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v2	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v4	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v8	= 3,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v16	= 4,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v32	= 5,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v48	= 6,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14_v64	= 7
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_StartSF_CSS_RA_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_Offset_RA_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_Offset_RA_r14_zero	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_Offset_RA_r14_oneEighth	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_Offset_RA_r14_oneFourth	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_Offset_RA_r14_threeEighth	= 3
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__npdcch_Offset_RA_r14;
typedef enum LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14 {
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n8	= 0,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n10	= 1,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n11	= 2,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n12	= 3,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n20	= 4,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n22	= 5,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n23	= 6,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n24	= 7,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n32	= 8,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n34	= 9,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n35	= 10,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n36	= 11,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n40	= 12,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n44	= 13,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n46	= 14,
	LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14_n48	= 15
} e_LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14__nprach_NumCBRA_StartSubcarriers_r14;

/* LTE_NPRACH-Parameters-NB-r14 */
typedef struct LTE_NPRACH_Parameters_NB_r14 {
	struct LTE_NPRACH_Parameters_NB_r14__nprach_Parameters_r14 {
		long	*nprach_Periodicity_r14;	/* OPTIONAL */
		long	*nprach_StartTime_r14;	/* OPTIONAL */
		long	*nprach_SubcarrierOffset_r14;	/* OPTIONAL */
		long	*nprach_NumSubcarriers_r14;	/* OPTIONAL */
		long	*nprach_SubcarrierMSG3_RangeStart_r14;	/* OPTIONAL */
		long	*npdcch_NumRepetitions_RA_r14;	/* OPTIONAL */
		long	*npdcch_StartSF_CSS_RA_r14;	/* OPTIONAL */
		long	*npdcch_Offset_RA_r14;	/* OPTIONAL */
		long	*nprach_NumCBRA_StartSubcarriers_r14;	/* OPTIONAL */
		long	*npdcch_CarrierIndex_r14;	/* OPTIONAL */
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nprach_Parameters_r14;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_NPRACH_Parameters_NB_r14_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_nprach_Periodicity_r14_3;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_nprach_StartTime_r14_12;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_nprach_SubcarrierOffset_r14_21;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_nprach_NumSubcarriers_r14_30;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_nprach_SubcarrierMSG3_RangeStart_r14_35;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_npdcch_NumRepetitions_RA_r14_40;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_npdcch_StartSF_CSS_RA_r14_57;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_npdcch_Offset_RA_r14_66;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_nprach_NumCBRA_StartSubcarriers_r14_71;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_NPRACH_Parameters_NB_r14;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_NPRACH_Parameters_NB_r14_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_NPRACH_Parameters_NB_r14_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_NPRACH_Parameters_NB_r14_H_ */
#include <asn_internal.h>
