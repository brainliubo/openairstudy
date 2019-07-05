/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_T_StatusProhibit_H_
#define	_LTE_T_StatusProhibit_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_T_StatusProhibit {
	LTE_T_StatusProhibit_ms0	= 0,
	LTE_T_StatusProhibit_ms5	= 1,
	LTE_T_StatusProhibit_ms10	= 2,
	LTE_T_StatusProhibit_ms15	= 3,
	LTE_T_StatusProhibit_ms20	= 4,
	LTE_T_StatusProhibit_ms25	= 5,
	LTE_T_StatusProhibit_ms30	= 6,
	LTE_T_StatusProhibit_ms35	= 7,
	LTE_T_StatusProhibit_ms40	= 8,
	LTE_T_StatusProhibit_ms45	= 9,
	LTE_T_StatusProhibit_ms50	= 10,
	LTE_T_StatusProhibit_ms55	= 11,
	LTE_T_StatusProhibit_ms60	= 12,
	LTE_T_StatusProhibit_ms65	= 13,
	LTE_T_StatusProhibit_ms70	= 14,
	LTE_T_StatusProhibit_ms75	= 15,
	LTE_T_StatusProhibit_ms80	= 16,
	LTE_T_StatusProhibit_ms85	= 17,
	LTE_T_StatusProhibit_ms90	= 18,
	LTE_T_StatusProhibit_ms95	= 19,
	LTE_T_StatusProhibit_ms100	= 20,
	LTE_T_StatusProhibit_ms105	= 21,
	LTE_T_StatusProhibit_ms110	= 22,
	LTE_T_StatusProhibit_ms115	= 23,
	LTE_T_StatusProhibit_ms120	= 24,
	LTE_T_StatusProhibit_ms125	= 25,
	LTE_T_StatusProhibit_ms130	= 26,
	LTE_T_StatusProhibit_ms135	= 27,
	LTE_T_StatusProhibit_ms140	= 28,
	LTE_T_StatusProhibit_ms145	= 29,
	LTE_T_StatusProhibit_ms150	= 30,
	LTE_T_StatusProhibit_ms155	= 31,
	LTE_T_StatusProhibit_ms160	= 32,
	LTE_T_StatusProhibit_ms165	= 33,
	LTE_T_StatusProhibit_ms170	= 34,
	LTE_T_StatusProhibit_ms175	= 35,
	LTE_T_StatusProhibit_ms180	= 36,
	LTE_T_StatusProhibit_ms185	= 37,
	LTE_T_StatusProhibit_ms190	= 38,
	LTE_T_StatusProhibit_ms195	= 39,
	LTE_T_StatusProhibit_ms200	= 40,
	LTE_T_StatusProhibit_ms205	= 41,
	LTE_T_StatusProhibit_ms210	= 42,
	LTE_T_StatusProhibit_ms215	= 43,
	LTE_T_StatusProhibit_ms220	= 44,
	LTE_T_StatusProhibit_ms225	= 45,
	LTE_T_StatusProhibit_ms230	= 46,
	LTE_T_StatusProhibit_ms235	= 47,
	LTE_T_StatusProhibit_ms240	= 48,
	LTE_T_StatusProhibit_ms245	= 49,
	LTE_T_StatusProhibit_ms250	= 50,
	LTE_T_StatusProhibit_ms300	= 51,
	LTE_T_StatusProhibit_ms350	= 52,
	LTE_T_StatusProhibit_ms400	= 53,
	LTE_T_StatusProhibit_ms450	= 54,
	LTE_T_StatusProhibit_ms500	= 55,
	LTE_T_StatusProhibit_ms800_v1310	= 56,
	LTE_T_StatusProhibit_ms1000_v1310	= 57,
	LTE_T_StatusProhibit_ms1200_v1310	= 58,
	LTE_T_StatusProhibit_ms1600_v1310	= 59,
	LTE_T_StatusProhibit_ms2000_v1310	= 60,
	LTE_T_StatusProhibit_ms2400_v1310	= 61,
	LTE_T_StatusProhibit_spare2	= 62,
	LTE_T_StatusProhibit_spare1	= 63
} e_LTE_T_StatusProhibit;

/* LTE_T-StatusProhibit */
typedef long	 LTE_T_StatusProhibit_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LTE_T_StatusProhibit_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LTE_T_StatusProhibit;
extern const asn_INTEGER_specifics_t asn_SPC_LTE_T_StatusProhibit_specs_1;
asn_struct_free_f LTE_T_StatusProhibit_free;
asn_struct_print_f LTE_T_StatusProhibit_print;
asn_constr_check_f LTE_T_StatusProhibit_constraint;
ber_type_decoder_f LTE_T_StatusProhibit_decode_ber;
der_type_encoder_f LTE_T_StatusProhibit_encode_der;
xer_type_decoder_f LTE_T_StatusProhibit_decode_xer;
xer_type_encoder_f LTE_T_StatusProhibit_encode_xer;
per_type_decoder_f LTE_T_StatusProhibit_decode_uper;
per_type_encoder_f LTE_T_StatusProhibit_encode_uper;
per_type_decoder_f LTE_T_StatusProhibit_decode_aper;
per_type_encoder_f LTE_T_StatusProhibit_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_T_StatusProhibit_H_ */
#include <asn_internal.h>
