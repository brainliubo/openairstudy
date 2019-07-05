/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_CQI-NPDCCH-NB-r14.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
asn_per_constraints_t asn_PER_type_LTE_CQI_NPDCCH_NB_r14_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  12 }	/* (0..12) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_LTE_CQI_NPDCCH_NB_r14_value2enum_1[] = {
	{ 0,	14,	"noMeasurements" },
	{ 1,	14,	"candidateRep-A" },
	{ 2,	14,	"candidateRep-B" },
	{ 3,	14,	"candidateRep-C" },
	{ 4,	14,	"candidateRep-D" },
	{ 5,	14,	"candidateRep-E" },
	{ 6,	14,	"candidateRep-F" },
	{ 7,	14,	"candidateRep-G" },
	{ 8,	14,	"candidateRep-H" },
	{ 9,	14,	"candidateRep-I" },
	{ 10,	14,	"candidateRep-J" },
	{ 11,	14,	"candidateRep-K" },
	{ 12,	14,	"candidateRep-L" }
};
static const unsigned int asn_MAP_LTE_CQI_NPDCCH_NB_r14_enum2value_1[] = {
	1,	/* candidateRep-A(1) */
	2,	/* candidateRep-B(2) */
	3,	/* candidateRep-C(3) */
	4,	/* candidateRep-D(4) */
	5,	/* candidateRep-E(5) */
	6,	/* candidateRep-F(6) */
	7,	/* candidateRep-G(7) */
	8,	/* candidateRep-H(8) */
	9,	/* candidateRep-I(9) */
	10,	/* candidateRep-J(10) */
	11,	/* candidateRep-K(11) */
	12,	/* candidateRep-L(12) */
	0	/* noMeasurements(0) */
};
const asn_INTEGER_specifics_t asn_SPC_LTE_CQI_NPDCCH_NB_r14_specs_1 = {
	asn_MAP_LTE_CQI_NPDCCH_NB_r14_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_CQI_NPDCCH_NB_r14_enum2value_1,	/* N => "tag"; sorted by N */
	13,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_CQI_NPDCCH_NB_r14_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_LTE_CQI_NPDCCH_NB_r14 = {
	"CQI-NPDCCH-NB-r14",
	"CQI-NPDCCH-NB-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_CQI_NPDCCH_NB_r14_tags_1,
	sizeof(asn_DEF_LTE_CQI_NPDCCH_NB_r14_tags_1)
		/sizeof(asn_DEF_LTE_CQI_NPDCCH_NB_r14_tags_1[0]), /* 1 */
	asn_DEF_LTE_CQI_NPDCCH_NB_r14_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_CQI_NPDCCH_NB_r14_tags_1)
		/sizeof(asn_DEF_LTE_CQI_NPDCCH_NB_r14_tags_1[0]), /* 1 */
	{ 0, &asn_PER_type_LTE_CQI_NPDCCH_NB_r14_constr_1, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_CQI_NPDCCH_NB_r14_specs_1	/* Additional specs */
};

