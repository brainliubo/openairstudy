/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_QuantityConfigUTRA_v1020_H_
#define	_LTE_QuantityConfigUTRA_v1020_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_FilterCoefficient.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* LTE_QuantityConfigUTRA-v1020 */
typedef struct LTE_QuantityConfigUTRA_v1020 {
	LTE_FilterCoefficient_t	*filterCoefficient2_FDD_r10;	/* DEFAULT 4 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_QuantityConfigUTRA_v1020_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_QuantityConfigUTRA_v1020;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_QuantityConfigUTRA_v1020_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_QuantityConfigUTRA_v1020_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_QuantityConfigUTRA_v1020_H_ */
#include <asn_internal.h>
