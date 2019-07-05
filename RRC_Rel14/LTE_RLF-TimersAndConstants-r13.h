/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RLF_TimersAndConstants_r13_H_
#define	_LTE_RLF_TimersAndConstants_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_RLF_TimersAndConstants_r13_PR {
	LTE_RLF_TimersAndConstants_r13_PR_NOTHING,	/* No components present */
	LTE_RLF_TimersAndConstants_r13_PR_release,
	LTE_RLF_TimersAndConstants_r13_PR_setup
} LTE_RLF_TimersAndConstants_r13_PR;
typedef enum LTE_RLF_TimersAndConstants_r13__setup__t301_v1310 {
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms2500	= 0,
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms3000	= 1,
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms3500	= 2,
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms4000	= 3,
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms5000	= 4,
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms6000	= 5,
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms8000	= 6,
	LTE_RLF_TimersAndConstants_r13__setup__t301_v1310_ms10000	= 7
} e_LTE_RLF_TimersAndConstants_r13__setup__t301_v1310;
typedef enum LTE_RLF_TimersAndConstants_r13__setup__ext1__t310_v1330 {
	LTE_RLF_TimersAndConstants_r13__setup__ext1__t310_v1330_ms4000	= 0,
	LTE_RLF_TimersAndConstants_r13__setup__ext1__t310_v1330_ms6000	= 1
} e_LTE_RLF_TimersAndConstants_r13__setup__ext1__t310_v1330;

/* LTE_RLF-TimersAndConstants-r13 */
typedef struct LTE_RLF_TimersAndConstants_r13 {
	LTE_RLF_TimersAndConstants_r13_PR present;
	union LTE_RLF_TimersAndConstants_r13_u {
		NULL_t	 release;
		struct LTE_RLF_TimersAndConstants_r13__setup {
			long	 t301_v1310;
			/*
			 * This type is extensible,
			 * possible extensions are below.
			 */
			struct LTE_RLF_TimersAndConstants_r13__setup__ext1 {
				long	*t310_v1330;	/* OPTIONAL */
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *ext1;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} setup;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RLF_TimersAndConstants_r13_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_t301_v1310_4;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_LTE_t310_v1330_15;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RLF_TimersAndConstants_r13;
extern asn_CHOICE_specifics_t asn_SPC_LTE_RLF_TimersAndConstants_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RLF_TimersAndConstants_r13_1[2];
extern asn_per_constraints_t asn_PER_type_LTE_RLF_TimersAndConstants_r13_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_RLF_TimersAndConstants_r13_H_ */
#include <asn_internal.h>
