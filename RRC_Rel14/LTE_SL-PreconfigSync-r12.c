/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-Sidelink-Preconf"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_SL-PreconfigSync-r12.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_per_constraints_t asn_PER_type_LTE_syncRefMinHyst_r12_constr_8 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  4 }	/* (0..4) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_syncRefDiffHyst_r12_constr_14 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  5 }	/* (0..5) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_syncTxPeriodic_r13_constr_23 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_LTE_syncRefMinHyst_r12_value2enum_8[] = {
	{ 0,	3,	"dB0" },
	{ 1,	3,	"dB3" },
	{ 2,	3,	"dB6" },
	{ 3,	3,	"dB9" },
	{ 4,	4,	"dB12" }
};
static const unsigned int asn_MAP_LTE_syncRefMinHyst_r12_enum2value_8[] = {
	0,	/* dB0(0) */
	4,	/* dB12(4) */
	1,	/* dB3(1) */
	2,	/* dB6(2) */
	3	/* dB9(3) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_syncRefMinHyst_r12_specs_8 = {
	asn_MAP_LTE_syncRefMinHyst_r12_value2enum_8,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_syncRefMinHyst_r12_enum2value_8,	/* N => "tag"; sorted by N */
	5,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_syncRefMinHyst_r12_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_syncRefMinHyst_r12_8 = {
	"syncRefMinHyst-r12",
	"syncRefMinHyst-r12",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_syncRefMinHyst_r12_tags_8,
	sizeof(asn_DEF_LTE_syncRefMinHyst_r12_tags_8)
		/sizeof(asn_DEF_LTE_syncRefMinHyst_r12_tags_8[0]) - 1, /* 1 */
	asn_DEF_LTE_syncRefMinHyst_r12_tags_8,	/* Same as above */
	sizeof(asn_DEF_LTE_syncRefMinHyst_r12_tags_8)
		/sizeof(asn_DEF_LTE_syncRefMinHyst_r12_tags_8[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_syncRefMinHyst_r12_constr_8, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_syncRefMinHyst_r12_specs_8	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_LTE_syncRefDiffHyst_r12_value2enum_14[] = {
	{ 0,	3,	"dB0" },
	{ 1,	3,	"dB3" },
	{ 2,	3,	"dB6" },
	{ 3,	3,	"dB9" },
	{ 4,	4,	"dB12" },
	{ 5,	5,	"dBinf" }
};
static const unsigned int asn_MAP_LTE_syncRefDiffHyst_r12_enum2value_14[] = {
	0,	/* dB0(0) */
	4,	/* dB12(4) */
	1,	/* dB3(1) */
	2,	/* dB6(2) */
	3,	/* dB9(3) */
	5	/* dBinf(5) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_syncRefDiffHyst_r12_specs_14 = {
	asn_MAP_LTE_syncRefDiffHyst_r12_value2enum_14,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_syncRefDiffHyst_r12_enum2value_14,	/* N => "tag"; sorted by N */
	6,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_syncRefDiffHyst_r12_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_syncRefDiffHyst_r12_14 = {
	"syncRefDiffHyst-r12",
	"syncRefDiffHyst-r12",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_syncRefDiffHyst_r12_tags_14,
	sizeof(asn_DEF_LTE_syncRefDiffHyst_r12_tags_14)
		/sizeof(asn_DEF_LTE_syncRefDiffHyst_r12_tags_14[0]) - 1, /* 1 */
	asn_DEF_LTE_syncRefDiffHyst_r12_tags_14,	/* Same as above */
	sizeof(asn_DEF_LTE_syncRefDiffHyst_r12_tags_14)
		/sizeof(asn_DEF_LTE_syncRefDiffHyst_r12_tags_14[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_syncRefDiffHyst_r12_constr_14, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_syncRefDiffHyst_r12_specs_14	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_LTE_syncTxPeriodic_r13_value2enum_23[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_LTE_syncTxPeriodic_r13_enum2value_23[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_syncTxPeriodic_r13_specs_23 = {
	asn_MAP_LTE_syncTxPeriodic_r13_value2enum_23,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_syncTxPeriodic_r13_enum2value_23,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_syncTxPeriodic_r13_tags_23[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_syncTxPeriodic_r13_23 = {
	"syncTxPeriodic-r13",
	"syncTxPeriodic-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_syncTxPeriodic_r13_tags_23,
	sizeof(asn_DEF_LTE_syncTxPeriodic_r13_tags_23)
		/sizeof(asn_DEF_LTE_syncTxPeriodic_r13_tags_23[0]) - 1, /* 1 */
	asn_DEF_LTE_syncTxPeriodic_r13_tags_23,	/* Same as above */
	sizeof(asn_DEF_LTE_syncTxPeriodic_r13_tags_23)
		/sizeof(asn_DEF_LTE_syncTxPeriodic_r13_tags_23[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_syncTxPeriodic_r13_constr_23, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_syncTxPeriodic_r13_specs_23	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext1_22[] = {
	{ ATF_POINTER, 1, offsetof(struct LTE_SL_PreconfigSync_r12__ext1, syncTxPeriodic_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_syncTxPeriodic_r13_23,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncTxPeriodic-r13"
		},
};
static const int asn_MAP_LTE_ext1_oms_22[] = { 0 };
static const ber_tlv_tag_t asn_DEF_LTE_ext1_tags_22[] = {
	(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext1_tag2el_22[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* syncTxPeriodic-r13 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext1_specs_22 = {
	sizeof(struct LTE_SL_PreconfigSync_r12__ext1),
	offsetof(struct LTE_SL_PreconfigSync_r12__ext1, _asn_ctx),
	asn_MAP_LTE_ext1_tag2el_22,
	1,	/* Count of tags in the map */
	asn_MAP_LTE_ext1_oms_22,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext1_22 = {
	"ext1",
	"ext1",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext1_tags_22,
	sizeof(asn_DEF_LTE_ext1_tags_22)
		/sizeof(asn_DEF_LTE_ext1_tags_22[0]) - 1, /* 1 */
	asn_DEF_LTE_ext1_tags_22,	/* Same as above */
	sizeof(asn_DEF_LTE_ext1_tags_22)
		/sizeof(asn_DEF_LTE_ext1_tags_22[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext1_22,
	1,	/* Elements count */
	&asn_SPC_LTE_ext1_specs_22	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_SL_PreconfigSync_r12_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, syncCP_Len_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_SL_CP_Len_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncCP-Len-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, syncOffsetIndicator1_r12),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_SL_OffsetIndicatorSync_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncOffsetIndicator1-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, syncOffsetIndicator2_r12),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_SL_OffsetIndicatorSync_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncOffsetIndicator2-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, syncTxParameters_r12),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_P0_SL_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncTxParameters-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, syncTxThreshOoC_r12),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_RSRP_RangeSL3_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncTxThreshOoC-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, filterCoefficient_r12),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_FilterCoefficient,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"filterCoefficient-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, syncRefMinHyst_r12),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_syncRefMinHyst_r12_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncRefMinHyst-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_PreconfigSync_r12, syncRefDiffHyst_r12),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_syncRefDiffHyst_r12_14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"syncRefDiffHyst-r12"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_SL_PreconfigSync_r12, ext1),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		0,
		&asn_DEF_LTE_ext1_22,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext1"
		},
};
static const int asn_MAP_LTE_SL_PreconfigSync_r12_oms_1[] = { 8 };
static const ber_tlv_tag_t asn_DEF_LTE_SL_PreconfigSync_r12_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_SL_PreconfigSync_r12_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* syncCP-Len-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* syncOffsetIndicator1-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* syncOffsetIndicator2-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* syncTxParameters-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* syncTxThreshOoC-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* filterCoefficient-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* syncRefMinHyst-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* syncRefDiffHyst-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 } /* ext1 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_SL_PreconfigSync_r12_specs_1 = {
	sizeof(struct LTE_SL_PreconfigSync_r12),
	offsetof(struct LTE_SL_PreconfigSync_r12, _asn_ctx),
	asn_MAP_LTE_SL_PreconfigSync_r12_tag2el_1,
	9,	/* Count of tags in the map */
	asn_MAP_LTE_SL_PreconfigSync_r12_oms_1,	/* Optional members */
	0, 1,	/* Root/Additions */
	8,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_SL_PreconfigSync_r12 = {
	"SL-PreconfigSync-r12",
	"SL-PreconfigSync-r12",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_SL_PreconfigSync_r12_tags_1,
	sizeof(asn_DEF_LTE_SL_PreconfigSync_r12_tags_1)
		/sizeof(asn_DEF_LTE_SL_PreconfigSync_r12_tags_1[0]), /* 1 */
	asn_DEF_LTE_SL_PreconfigSync_r12_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_SL_PreconfigSync_r12_tags_1)
		/sizeof(asn_DEF_LTE_SL_PreconfigSync_r12_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_SL_PreconfigSync_r12_1,
	9,	/* Elements count */
	&asn_SPC_LTE_SL_PreconfigSync_r12_specs_1	/* Additional specs */
};

