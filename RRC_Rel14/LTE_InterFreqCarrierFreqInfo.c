/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_InterFreqCarrierFreqInfo.h"

static int asn_DFL_13_cmp_15(const void *sptr) {
	const LTE_Q_OffsetRange_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 15 */
	return (*st != 15);
}
static int asn_DFL_13_set_15(void **sptr) {
	LTE_Q_OffsetRange_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 15 */
	*st = 15;
	return 0;
}
static asn_TYPE_member_t asn_MBR_LTE_threshX_Q_r9_19[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo__ext1__threshX_Q_r9, threshX_HighQ_r9),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ReselectionThresholdQ_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"threshX-HighQ-r9"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo__ext1__threshX_Q_r9, threshX_LowQ_r9),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ReselectionThresholdQ_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"threshX-LowQ-r9"
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_threshX_Q_r9_tags_19[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_threshX_Q_r9_tag2el_19[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* threshX-HighQ-r9 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* threshX-LowQ-r9 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_threshX_Q_r9_specs_19 = {
	sizeof(struct LTE_InterFreqCarrierFreqInfo__ext1__threshX_Q_r9),
	offsetof(struct LTE_InterFreqCarrierFreqInfo__ext1__threshX_Q_r9, _asn_ctx),
	asn_MAP_LTE_threshX_Q_r9_tag2el_19,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_threshX_Q_r9_19 = {
	"threshX-Q-r9",
	"threshX-Q-r9",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_threshX_Q_r9_tags_19,
	sizeof(asn_DEF_LTE_threshX_Q_r9_tags_19)
		/sizeof(asn_DEF_LTE_threshX_Q_r9_tags_19[0]) - 1, /* 1 */
	asn_DEF_LTE_threshX_Q_r9_tags_19,	/* Same as above */
	sizeof(asn_DEF_LTE_threshX_Q_r9_tags_19)
		/sizeof(asn_DEF_LTE_threshX_Q_r9_tags_19[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_threshX_Q_r9_19,
	2,	/* Elements count */
	&asn_SPC_LTE_threshX_Q_r9_specs_19	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext1_17[] = {
	{ ATF_POINTER, 2, offsetof(struct LTE_InterFreqCarrierFreqInfo__ext1, q_QualMin_r9),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Q_QualMin_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"q-QualMin-r9"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo__ext1, threshX_Q_r9),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_LTE_threshX_Q_r9_19,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"threshX-Q-r9"
		},
};
static const int asn_MAP_LTE_ext1_oms_17[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_LTE_ext1_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext1_tag2el_17[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* q-QualMin-r9 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* threshX-Q-r9 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext1_specs_17 = {
	sizeof(struct LTE_InterFreqCarrierFreqInfo__ext1),
	offsetof(struct LTE_InterFreqCarrierFreqInfo__ext1, _asn_ctx),
	asn_MAP_LTE_ext1_tag2el_17,
	2,	/* Count of tags in the map */
	asn_MAP_LTE_ext1_oms_17,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext1_17 = {
	"ext1",
	"ext1",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext1_tags_17,
	sizeof(asn_DEF_LTE_ext1_tags_17)
		/sizeof(asn_DEF_LTE_ext1_tags_17[0]) - 1, /* 1 */
	asn_DEF_LTE_ext1_tags_17,	/* Same as above */
	sizeof(asn_DEF_LTE_ext1_tags_17)
		/sizeof(asn_DEF_LTE_ext1_tags_17[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext1_17,
	2,	/* Elements count */
	&asn_SPC_LTE_ext1_specs_17	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext2_22[] = {
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo__ext2, q_QualMinWB_r11),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Q_QualMin_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"q-QualMinWB-r11"
		},
};
static const int asn_MAP_LTE_ext2_oms_22[] = { 0 };
static const ber_tlv_tag_t asn_DEF_LTE_ext2_tags_22[] = {
	(ASN_TAG_CLASS_CONTEXT | (15 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext2_tag2el_22[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* q-QualMinWB-r11 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext2_specs_22 = {
	sizeof(struct LTE_InterFreqCarrierFreqInfo__ext2),
	offsetof(struct LTE_InterFreqCarrierFreqInfo__ext2, _asn_ctx),
	asn_MAP_LTE_ext2_tag2el_22,
	1,	/* Count of tags in the map */
	asn_MAP_LTE_ext2_oms_22,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext2_22 = {
	"ext2",
	"ext2",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext2_tags_22,
	sizeof(asn_DEF_LTE_ext2_tags_22)
		/sizeof(asn_DEF_LTE_ext2_tags_22[0]) - 1, /* 1 */
	asn_DEF_LTE_ext2_tags_22,	/* Same as above */
	sizeof(asn_DEF_LTE_ext2_tags_22)
		/sizeof(asn_DEF_LTE_ext2_tags_22[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext2_22,
	1,	/* Elements count */
	&asn_SPC_LTE_ext2_specs_22	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_InterFreqCarrierFreqInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, dl_CarrierFreq),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ARFCN_ValueEUTRA,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CarrierFreq"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, q_RxLevMin),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Q_RxLevMin,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"q-RxLevMin"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo, p_Max),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_P_Max,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"p-Max"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, t_ReselectionEUTRA),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_T_Reselection,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"t-ReselectionEUTRA"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo, t_ReselectionEUTRA_SF),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_SpeedStateScaleFactors,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"t-ReselectionEUTRA-SF"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, threshX_High),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ReselectionThreshold,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"threshX-High"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, threshX_Low),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ReselectionThreshold,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"threshX-Low"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, allowedMeasBandwidth),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_AllowedMeasBandwidth,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"allowedMeasBandwidth"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, presenceAntennaPort1),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PresenceAntennaPort1,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"presenceAntennaPort1"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo, cellReselectionPriority),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CellReselectionPriority,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellReselectionPriority"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo, neighCellConfig),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_NeighCellConfig,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"neighCellConfig"
		},
	{ ATF_POINTER, 5, offsetof(struct LTE_InterFreqCarrierFreqInfo, q_OffsetFreq),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Q_OffsetRange,
		0,
		{ 0, 0, 0 },
		&asn_DFL_13_cmp_15,	/* Compare DEFAULT 15 */
		&asn_DFL_13_set_15,	/* Set DEFAULT 15 */
		"q-OffsetFreq"
		},
	{ ATF_POINTER, 4, offsetof(struct LTE_InterFreqCarrierFreqInfo, interFreqNeighCellList),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_InterFreqNeighCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interFreqNeighCellList"
		},
	{ ATF_POINTER, 3, offsetof(struct LTE_InterFreqCarrierFreqInfo, interFreqBlackCellList),
		(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_InterFreqBlackCellList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interFreqBlackCellList"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_InterFreqCarrierFreqInfo, ext1),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		0,
		&asn_DEF_LTE_ext1_17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext1"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo, ext2),
		(ASN_TAG_CLASS_CONTEXT | (15 << 2)),
		0,
		&asn_DEF_LTE_ext2_22,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext2"
		},
};
static const int asn_MAP_LTE_InterFreqCarrierFreqInfo_oms_1[] = { 2, 4, 9, 11, 12, 13, 14, 15 };
static const ber_tlv_tag_t asn_DEF_LTE_InterFreqCarrierFreqInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_InterFreqCarrierFreqInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-CarrierFreq */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* q-RxLevMin */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* p-Max */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* t-ReselectionEUTRA */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* t-ReselectionEUTRA-SF */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* threshX-High */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* threshX-Low */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* allowedMeasBandwidth */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* presenceAntennaPort1 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* cellReselectionPriority */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* neighCellConfig */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* q-OffsetFreq */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 }, /* interFreqNeighCellList */
    { (ASN_TAG_CLASS_CONTEXT | (13 << 2)), 13, 0, 0 }, /* interFreqBlackCellList */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 14, 0, 0 }, /* ext1 */
    { (ASN_TAG_CLASS_CONTEXT | (15 << 2)), 15, 0, 0 } /* ext2 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_InterFreqCarrierFreqInfo_specs_1 = {
	sizeof(struct LTE_InterFreqCarrierFreqInfo),
	offsetof(struct LTE_InterFreqCarrierFreqInfo, _asn_ctx),
	asn_MAP_LTE_InterFreqCarrierFreqInfo_tag2el_1,
	16,	/* Count of tags in the map */
	asn_MAP_LTE_InterFreqCarrierFreqInfo_oms_1,	/* Optional members */
	6, 2,	/* Root/Additions */
	14,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_InterFreqCarrierFreqInfo = {
	"InterFreqCarrierFreqInfo",
	"InterFreqCarrierFreqInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_InterFreqCarrierFreqInfo_tags_1,
	sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_tags_1)
		/sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_tags_1[0]), /* 1 */
	asn_DEF_LTE_InterFreqCarrierFreqInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_tags_1)
		/sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_InterFreqCarrierFreqInfo_1,
	16,	/* Elements count */
	&asn_SPC_LTE_InterFreqCarrierFreqInfo_specs_1	/* Additional specs */
};

