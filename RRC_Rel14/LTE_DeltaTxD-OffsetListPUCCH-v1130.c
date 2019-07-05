/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_DeltaTxD-OffsetListPUCCH-v1130.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_per_constraints_t asn_PER_type_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_value2enum_2[] = {
	{ 0,	3,	"dB0" },
	{ 1,	4,	"dB-1" }
};
static const unsigned int asn_MAP_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_enum2value_2[] = {
	1,	/* dB-1(1) */
	0	/* dB0(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_specs_2 = {
	asn_MAP_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_enum2value_2,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_2 = {
	"deltaTxD-OffsetPUCCH-Format1bCS-r11",
	"deltaTxD-OffsetPUCCH-Format1bCS-r11",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_tags_2,
	sizeof(asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_tags_2)
		/sizeof(asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_tags_2[0]) - 1, /* 1 */
	asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_tags_2,	/* Same as above */
	sizeof(asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_tags_2)
		/sizeof(asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_tags_2[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_DeltaTxD_OffsetListPUCCH_v1130_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_DeltaTxD_OffsetListPUCCH_v1130, deltaTxD_OffsetPUCCH_Format1bCS_r11),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_deltaTxD_OffsetPUCCH_Format1bCS_r11_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"deltaTxD-OffsetPUCCH-Format1bCS-r11"
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_DeltaTxD_OffsetListPUCCH_v1130_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* deltaTxD-OffsetPUCCH-Format1bCS-r11 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_DeltaTxD_OffsetListPUCCH_v1130_specs_1 = {
	sizeof(struct LTE_DeltaTxD_OffsetListPUCCH_v1130),
	offsetof(struct LTE_DeltaTxD_OffsetListPUCCH_v1130, _asn_ctx),
	asn_MAP_LTE_DeltaTxD_OffsetListPUCCH_v1130_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130 = {
	"DeltaTxD-OffsetListPUCCH-v1130",
	"DeltaTxD-OffsetListPUCCH-v1130",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130_tags_1,
	sizeof(asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130_tags_1)
		/sizeof(asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130_tags_1[0]), /* 1 */
	asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130_tags_1)
		/sizeof(asn_DEF_LTE_DeltaTxD_OffsetListPUCCH_v1130_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_DeltaTxD_OffsetListPUCCH_v1130_1,
	1,	/* Elements count */
	&asn_SPC_LTE_DeltaTxD_OffsetListPUCCH_v1130_specs_1	/* Additional specs */
};

