/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_RadioResourceConfigCommonSIB.h"

static asn_TYPE_member_t asn_MBR_LTE_ext1_13[] = {
	{ ATF_POINTER, 1, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext1, uplinkPowerControlCommon_v1020),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_UplinkPowerControlCommon_v1020,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uplinkPowerControlCommon-v1020"
		},
};
static const int asn_MAP_LTE_ext1_oms_13[] = { 0 };
static const ber_tlv_tag_t asn_DEF_LTE_ext1_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext1_tag2el_13[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* uplinkPowerControlCommon-v1020 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext1_specs_13 = {
	sizeof(struct LTE_RadioResourceConfigCommonSIB__ext1),
	offsetof(struct LTE_RadioResourceConfigCommonSIB__ext1, _asn_ctx),
	asn_MAP_LTE_ext1_tag2el_13,
	1,	/* Count of tags in the map */
	asn_MAP_LTE_ext1_oms_13,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext1_13 = {
	"ext1",
	"ext1",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext1_tags_13,
	sizeof(asn_DEF_LTE_ext1_tags_13)
		/sizeof(asn_DEF_LTE_ext1_tags_13[0]) - 1, /* 1 */
	asn_DEF_LTE_ext1_tags_13,	/* Same as above */
	sizeof(asn_DEF_LTE_ext1_tags_13)
		/sizeof(asn_DEF_LTE_ext1_tags_13[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext1_13,
	1,	/* Elements count */
	&asn_SPC_LTE_ext1_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext2_15[] = {
	{ ATF_POINTER, 1, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext2, rach_ConfigCommon_v1250),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_RACH_ConfigCommon_v1250,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rach-ConfigCommon-v1250"
		},
};
static const int asn_MAP_LTE_ext2_oms_15[] = { 0 };
static const ber_tlv_tag_t asn_DEF_LTE_ext2_tags_15[] = {
	(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext2_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* rach-ConfigCommon-v1250 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext2_specs_15 = {
	sizeof(struct LTE_RadioResourceConfigCommonSIB__ext2),
	offsetof(struct LTE_RadioResourceConfigCommonSIB__ext2, _asn_ctx),
	asn_MAP_LTE_ext2_tag2el_15,
	1,	/* Count of tags in the map */
	asn_MAP_LTE_ext2_oms_15,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext2_15 = {
	"ext2",
	"ext2",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext2_tags_15,
	sizeof(asn_DEF_LTE_ext2_tags_15)
		/sizeof(asn_DEF_LTE_ext2_tags_15[0]) - 1, /* 1 */
	asn_DEF_LTE_ext2_tags_15,	/* Same as above */
	sizeof(asn_DEF_LTE_ext2_tags_15)
		/sizeof(asn_DEF_LTE_ext2_tags_15[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext2_15,
	1,	/* Elements count */
	&asn_SPC_LTE_ext2_specs_15	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext3_17[] = {
	{ ATF_POINTER, 1, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext3, pusch_ConfigCommon_v1270),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PUSCH_ConfigCommon_v1270,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pusch-ConfigCommon-v1270"
		},
};
static const int asn_MAP_LTE_ext3_oms_17[] = { 0 };
static const ber_tlv_tag_t asn_DEF_LTE_ext3_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext3_tag2el_17[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* pusch-ConfigCommon-v1270 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext3_specs_17 = {
	sizeof(struct LTE_RadioResourceConfigCommonSIB__ext3),
	offsetof(struct LTE_RadioResourceConfigCommonSIB__ext3, _asn_ctx),
	asn_MAP_LTE_ext3_tag2el_17,
	1,	/* Count of tags in the map */
	asn_MAP_LTE_ext3_oms_17,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext3_17 = {
	"ext3",
	"ext3",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext3_tags_17,
	sizeof(asn_DEF_LTE_ext3_tags_17)
		/sizeof(asn_DEF_LTE_ext3_tags_17[0]) - 1, /* 1 */
	asn_DEF_LTE_ext3_tags_17,	/* Same as above */
	sizeof(asn_DEF_LTE_ext3_tags_17)
		/sizeof(asn_DEF_LTE_ext3_tags_17[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext3_17,
	1,	/* Elements count */
	&asn_SPC_LTE_ext3_specs_17	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext4_19[] = {
	{ ATF_POINTER, 7, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, bcch_Config_v1310),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_BCCH_Config_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"bcch-Config-v1310"
		},
	{ ATF_POINTER, 6, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, pcch_Config_v1310),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PCCH_Config_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pcch-Config-v1310"
		},
	{ ATF_POINTER, 5, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, freqHoppingParameters_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_FreqHoppingParameters_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"freqHoppingParameters-r13"
		},
	{ ATF_POINTER, 4, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, pdsch_ConfigCommon_v1310),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PDSCH_ConfigCommon_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pdsch-ConfigCommon-v1310"
		},
	{ ATF_POINTER, 3, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, pusch_ConfigCommon_v1310),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PUSCH_ConfigCommon_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pusch-ConfigCommon-v1310"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, prach_ConfigCommon_v1310),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PRACH_ConfigSIB_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"prach-ConfigCommon-v1310"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, pucch_ConfigCommon_v1310),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PUCCH_ConfigCommon_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pucch-ConfigCommon-v1310"
		},
};
static const int asn_MAP_LTE_ext4_oms_19[] = { 0, 1, 2, 3, 4, 5, 6 };
static const ber_tlv_tag_t asn_DEF_LTE_ext4_tags_19[] = {
	(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext4_tag2el_19[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* bcch-Config-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* pcch-Config-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* freqHoppingParameters-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* pdsch-ConfigCommon-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* pusch-ConfigCommon-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* prach-ConfigCommon-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* pucch-ConfigCommon-v1310 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext4_specs_19 = {
	sizeof(struct LTE_RadioResourceConfigCommonSIB__ext4),
	offsetof(struct LTE_RadioResourceConfigCommonSIB__ext4, _asn_ctx),
	asn_MAP_LTE_ext4_tag2el_19,
	7,	/* Count of tags in the map */
	asn_MAP_LTE_ext4_oms_19,	/* Optional members */
	7, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext4_19 = {
	"ext4",
	"ext4",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext4_tags_19,
	sizeof(asn_DEF_LTE_ext4_tags_19)
		/sizeof(asn_DEF_LTE_ext4_tags_19[0]) - 1, /* 1 */
	asn_DEF_LTE_ext4_tags_19,	/* Same as above */
	sizeof(asn_DEF_LTE_ext4_tags_19)
		/sizeof(asn_DEF_LTE_ext4_tags_19[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext4_19,
	7,	/* Elements count */
	&asn_SPC_LTE_ext4_specs_19	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext5_27[] = {
	{ ATF_POINTER, 3, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext5, highSpeedConfig_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_HighSpeedConfig_r14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"highSpeedConfig-r14"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext5, prach_Config_v1430),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PRACH_Config_v1430,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"prach-Config-v1430"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_RadioResourceConfigCommonSIB__ext5, pucch_ConfigCommon_v1430),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PUCCH_ConfigCommon_v1430,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pucch-ConfigCommon-v1430"
		},
};
static const int asn_MAP_LTE_ext5_oms_27[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_LTE_ext5_tags_27[] = {
	(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext5_tag2el_27[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* highSpeedConfig-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* prach-Config-v1430 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* pucch-ConfigCommon-v1430 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext5_specs_27 = {
	sizeof(struct LTE_RadioResourceConfigCommonSIB__ext5),
	offsetof(struct LTE_RadioResourceConfigCommonSIB__ext5, _asn_ctx),
	asn_MAP_LTE_ext5_tag2el_27,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_ext5_oms_27,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext5_27 = {
	"ext5",
	"ext5",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext5_tags_27,
	sizeof(asn_DEF_LTE_ext5_tags_27)
		/sizeof(asn_DEF_LTE_ext5_tags_27[0]) - 1, /* 1 */
	asn_DEF_LTE_ext5_tags_27,	/* Same as above */
	sizeof(asn_DEF_LTE_ext5_tags_27)
		/sizeof(asn_DEF_LTE_ext5_tags_27[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext5_27,
	3,	/* Elements count */
	&asn_SPC_LTE_ext5_specs_27	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_RadioResourceConfigCommonSIB_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, rach_ConfigCommon),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_RACH_ConfigCommon,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rach-ConfigCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, bcch_Config),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_BCCH_Config,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"bcch-Config"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, pcch_Config),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PCCH_Config,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pcch-Config"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, prach_Config),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PRACH_ConfigSIB,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"prach-Config"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, pdsch_ConfigCommon),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PDSCH_ConfigCommon,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pdsch-ConfigCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, pusch_ConfigCommon),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PUSCH_ConfigCommon,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pusch-ConfigCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, pucch_ConfigCommon),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PUCCH_ConfigCommon,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"pucch-ConfigCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, soundingRS_UL_ConfigCommon),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_SoundingRS_UL_ConfigCommon,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"soundingRS-UL-ConfigCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, uplinkPowerControlCommon),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_UplinkPowerControlCommon,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uplinkPowerControlCommon"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RadioResourceConfigCommonSIB, ul_CyclicPrefixLength),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_UL_CyclicPrefixLength,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-CyclicPrefixLength"
		},
	{ ATF_POINTER, 5, offsetof(struct LTE_RadioResourceConfigCommonSIB, ext1),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		0,
		&asn_DEF_LTE_ext1_13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext1"
		},
	{ ATF_POINTER, 4, offsetof(struct LTE_RadioResourceConfigCommonSIB, ext2),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		0,
		&asn_DEF_LTE_ext2_15,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext2"
		},
	{ ATF_POINTER, 3, offsetof(struct LTE_RadioResourceConfigCommonSIB, ext3),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		0,
		&asn_DEF_LTE_ext3_17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext3"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_RadioResourceConfigCommonSIB, ext4),
		(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
		0,
		&asn_DEF_LTE_ext4_19,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext4"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_RadioResourceConfigCommonSIB, ext5),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		0,
		&asn_DEF_LTE_ext5_27,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext5"
		},
};
static const int asn_MAP_LTE_RadioResourceConfigCommonSIB_oms_1[] = { 10, 11, 12, 13, 14 };
static const ber_tlv_tag_t asn_DEF_LTE_RadioResourceConfigCommonSIB_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_RadioResourceConfigCommonSIB_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rach-ConfigCommon */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* bcch-Config */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* pcch-Config */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* prach-Config */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* pdsch-ConfigCommon */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* pusch-ConfigCommon */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* pucch-ConfigCommon */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* soundingRS-UL-ConfigCommon */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* uplinkPowerControlCommon */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* ul-CyclicPrefixLength */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* ext1 */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* ext2 */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 }, /* ext3 */
    { (ASN_TAG_CLASS_CONTEXT | (13 << 2)), 13, 0, 0 }, /* ext4 */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 14, 0, 0 } /* ext5 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_RadioResourceConfigCommonSIB_specs_1 = {
	sizeof(struct LTE_RadioResourceConfigCommonSIB),
	offsetof(struct LTE_RadioResourceConfigCommonSIB, _asn_ctx),
	asn_MAP_LTE_RadioResourceConfigCommonSIB_tag2el_1,
	15,	/* Count of tags in the map */
	asn_MAP_LTE_RadioResourceConfigCommonSIB_oms_1,	/* Optional members */
	0, 5,	/* Root/Additions */
	10,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_RadioResourceConfigCommonSIB = {
	"RadioResourceConfigCommonSIB",
	"RadioResourceConfigCommonSIB",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_RadioResourceConfigCommonSIB_tags_1,
	sizeof(asn_DEF_LTE_RadioResourceConfigCommonSIB_tags_1)
		/sizeof(asn_DEF_LTE_RadioResourceConfigCommonSIB_tags_1[0]), /* 1 */
	asn_DEF_LTE_RadioResourceConfigCommonSIB_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_RadioResourceConfigCommonSIB_tags_1)
		/sizeof(asn_DEF_LTE_RadioResourceConfigCommonSIB_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_RadioResourceConfigCommonSIB_1,
	15,	/* Elements count */
	&asn_SPC_LTE_RadioResourceConfigCommonSIB_specs_1	/* Additional specs */
};

