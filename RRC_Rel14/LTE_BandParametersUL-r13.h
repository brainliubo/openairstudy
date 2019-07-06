/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_BandParametersUL_r13_H_
#define	_LTE_BandParametersUL_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include "LTE_CA-MIMO-ParametersUL-r10.h"

#ifdef __cplusplus
extern "C" {
#endif

/* LTE_BandParametersUL-r13 */
typedef LTE_CA_MIMO_ParametersUL_r10_t	 LTE_BandParametersUL_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_BandParametersUL_r13;
asn_struct_free_f LTE_BandParametersUL_r13_free;
asn_struct_print_f LTE_BandParametersUL_r13_print;
asn_constr_check_f LTE_BandParametersUL_r13_constraint;
ber_type_decoder_f LTE_BandParametersUL_r13_decode_ber;
der_type_encoder_f LTE_BandParametersUL_r13_encode_der;
xer_type_decoder_f LTE_BandParametersUL_r13_decode_xer;
xer_type_encoder_f LTE_BandParametersUL_r13_encode_xer;
per_type_decoder_f LTE_BandParametersUL_r13_decode_uper;
per_type_encoder_f LTE_BandParametersUL_r13_encode_uper;
per_type_decoder_f LTE_BandParametersUL_r13_decode_aper;
per_type_encoder_f LTE_BandParametersUL_r13_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_BandParametersUL_r13_H_ */
#include <asn_internal.h>