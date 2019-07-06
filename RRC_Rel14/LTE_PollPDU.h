/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_PollPDU_H_
#define	_LTE_PollPDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_PollPDU {
	LTE_PollPDU_p4	= 0,
	LTE_PollPDU_p8	= 1,
	LTE_PollPDU_p16	= 2,
	LTE_PollPDU_p32	= 3,
	LTE_PollPDU_p64	= 4,
	LTE_PollPDU_p128	= 5,
	LTE_PollPDU_p256	= 6,
	LTE_PollPDU_pInfinity	= 7
} e_LTE_PollPDU;

/* LTE_PollPDU */
typedef long	 LTE_PollPDU_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LTE_PollPDU_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LTE_PollPDU;
extern const asn_INTEGER_specifics_t asn_SPC_LTE_PollPDU_specs_1;
asn_struct_free_f LTE_PollPDU_free;
asn_struct_print_f LTE_PollPDU_print;
asn_constr_check_f LTE_PollPDU_constraint;
ber_type_decoder_f LTE_PollPDU_decode_ber;
der_type_encoder_f LTE_PollPDU_encode_der;
xer_type_decoder_f LTE_PollPDU_decode_xer;
xer_type_encoder_f LTE_PollPDU_encode_xer;
per_type_decoder_f LTE_PollPDU_decode_uper;
per_type_encoder_f LTE_PollPDU_encode_uper;
per_type_decoder_f LTE_PollPDU_decode_aper;
per_type_encoder_f LTE_PollPDU_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_PollPDU_H_ */
#include <asn_internal.h>