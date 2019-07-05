/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_InterFreqCarrierFreqInfo-NB-r13.h"

static int
memb_LTE_delta_RxLevMin_v1350_constraint_11(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -8 && value <= -1)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_per_constraints_t asn_PER_memb_LTE_delta_RxLevMin_v1350_constr_12 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3, -8, -1 }	/* (-8..-1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_powerClass14dBm_Offset_r14_constr_14 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  5 }	/* (0..5) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_ce_AuthorisationOffset_r14_constr_21 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  6 }	/* (0..6) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static int asn_DFL_6_cmp_15(const void *sptr) {
	const LTE_Q_OffsetRange_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 15 */
	return (*st != 15);
}
static int asn_DFL_6_set_15(void **sptr) {
	LTE_Q_OffsetRange_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 15 */
	*st = 15;
	return 0;
}
static asn_TYPE_member_t asn_MBR_LTE_ext1_11[] = {
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13__ext1, delta_RxLevMin_v1350),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_delta_RxLevMin_v1350_constr_12,  memb_LTE_delta_RxLevMin_v1350_constraint_11 },
		0, 0, /* No default value */
		"delta-RxLevMin-v1350"
		},
};
static const int asn_MAP_LTE_ext1_oms_11[] = { 0 };
static const ber_tlv_tag_t asn_DEF_LTE_ext1_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext1_tag2el_11[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* delta-RxLevMin-v1350 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext1_specs_11 = {
	sizeof(struct LTE_InterFreqCarrierFreqInfo_NB_r13__ext1),
	offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13__ext1, _asn_ctx),
	asn_MAP_LTE_ext1_tag2el_11,
	1,	/* Count of tags in the map */
	asn_MAP_LTE_ext1_oms_11,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext1_11 = {
	"ext1",
	"ext1",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext1_tags_11,
	sizeof(asn_DEF_LTE_ext1_tags_11)
		/sizeof(asn_DEF_LTE_ext1_tags_11[0]) - 1, /* 1 */
	asn_DEF_LTE_ext1_tags_11,	/* Same as above */
	sizeof(asn_DEF_LTE_ext1_tags_11)
		/sizeof(asn_DEF_LTE_ext1_tags_11[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext1_11,
	1,	/* Elements count */
	&asn_SPC_LTE_ext1_specs_11	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_LTE_powerClass14dBm_Offset_r14_value2enum_14[] = {
	{ 0,	4,	"dB-6" },
	{ 1,	4,	"dB-3" },
	{ 2,	3,	"dB3" },
	{ 3,	3,	"dB6" },
	{ 4,	3,	"dB9" },
	{ 5,	4,	"dB12" }
};
static const unsigned int asn_MAP_LTE_powerClass14dBm_Offset_r14_enum2value_14[] = {
	1,	/* dB-3(1) */
	0,	/* dB-6(0) */
	5,	/* dB12(5) */
	2,	/* dB3(2) */
	3,	/* dB6(3) */
	4	/* dB9(4) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_powerClass14dBm_Offset_r14_specs_14 = {
	asn_MAP_LTE_powerClass14dBm_Offset_r14_value2enum_14,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_powerClass14dBm_Offset_r14_enum2value_14,	/* N => "tag"; sorted by N */
	6,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_powerClass14dBm_Offset_r14_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_powerClass14dBm_Offset_r14_14 = {
	"powerClass14dBm-Offset-r14",
	"powerClass14dBm-Offset-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_powerClass14dBm_Offset_r14_tags_14,
	sizeof(asn_DEF_LTE_powerClass14dBm_Offset_r14_tags_14)
		/sizeof(asn_DEF_LTE_powerClass14dBm_Offset_r14_tags_14[0]) - 1, /* 1 */
	asn_DEF_LTE_powerClass14dBm_Offset_r14_tags_14,	/* Same as above */
	sizeof(asn_DEF_LTE_powerClass14dBm_Offset_r14_tags_14)
		/sizeof(asn_DEF_LTE_powerClass14dBm_Offset_r14_tags_14[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_powerClass14dBm_Offset_r14_constr_14, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_powerClass14dBm_Offset_r14_specs_14	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_LTE_ce_AuthorisationOffset_r14_value2enum_21[] = {
	{ 0,	3,	"dB5" },
	{ 1,	4,	"dB10" },
	{ 2,	4,	"dB15" },
	{ 3,	4,	"dB20" },
	{ 4,	4,	"dB25" },
	{ 5,	4,	"dB30" },
	{ 6,	4,	"dB35" }
};
static const unsigned int asn_MAP_LTE_ce_AuthorisationOffset_r14_enum2value_21[] = {
	1,	/* dB10(1) */
	2,	/* dB15(2) */
	3,	/* dB20(3) */
	4,	/* dB25(4) */
	5,	/* dB30(5) */
	6,	/* dB35(6) */
	0	/* dB5(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_ce_AuthorisationOffset_r14_specs_21 = {
	asn_MAP_LTE_ce_AuthorisationOffset_r14_value2enum_21,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_ce_AuthorisationOffset_r14_enum2value_21,	/* N => "tag"; sorted by N */
	7,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_ce_AuthorisationOffset_r14_tags_21[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ce_AuthorisationOffset_r14_21 = {
	"ce-AuthorisationOffset-r14",
	"ce-AuthorisationOffset-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_ce_AuthorisationOffset_r14_tags_21,
	sizeof(asn_DEF_LTE_ce_AuthorisationOffset_r14_tags_21)
		/sizeof(asn_DEF_LTE_ce_AuthorisationOffset_r14_tags_21[0]) - 1, /* 1 */
	asn_DEF_LTE_ce_AuthorisationOffset_r14_tags_21,	/* Same as above */
	sizeof(asn_DEF_LTE_ce_AuthorisationOffset_r14_tags_21)
		/sizeof(asn_DEF_LTE_ce_AuthorisationOffset_r14_tags_21[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_ce_AuthorisationOffset_r14_constr_21, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_ce_AuthorisationOffset_r14_specs_21	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext2_13[] = {
	{ ATF_POINTER, 2, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13__ext2, powerClass14dBm_Offset_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_powerClass14dBm_Offset_r14_14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"powerClass14dBm-Offset-r14"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13__ext2, ce_AuthorisationOffset_r14),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ce_AuthorisationOffset_r14_21,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ce-AuthorisationOffset-r14"
		},
};
static const int asn_MAP_LTE_ext2_oms_13[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_LTE_ext2_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext2_tag2el_13[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* powerClass14dBm-Offset-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ce-AuthorisationOffset-r14 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext2_specs_13 = {
	sizeof(struct LTE_InterFreqCarrierFreqInfo_NB_r13__ext2),
	offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13__ext2, _asn_ctx),
	asn_MAP_LTE_ext2_tag2el_13,
	2,	/* Count of tags in the map */
	asn_MAP_LTE_ext2_oms_13,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext2_13 = {
	"ext2",
	"ext2",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext2_tags_13,
	sizeof(asn_DEF_LTE_ext2_tags_13)
		/sizeof(asn_DEF_LTE_ext2_tags_13[0]) - 1, /* 1 */
	asn_DEF_LTE_ext2_tags_13,	/* Same as above */
	sizeof(asn_DEF_LTE_ext2_tags_13)
		/sizeof(asn_DEF_LTE_ext2_tags_13[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext2_13,
	2,	/* Elements count */
	&asn_SPC_LTE_ext2_specs_13	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_InterFreqCarrierFreqInfo_NB_r13_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, dl_CarrierFreq_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CarrierFreq_NB_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CarrierFreq-r13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, q_RxLevMin_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Q_RxLevMin,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"q-RxLevMin-r13"
		},
	{ ATF_POINTER, 8, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, q_QualMin_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Q_QualMin_r9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"q-QualMin-r13"
		},
	{ ATF_POINTER, 7, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, p_Max_r13),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_P_Max,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"p-Max-r13"
		},
	{ ATF_POINTER, 6, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, q_OffsetFreq_r13),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Q_OffsetRange,
		0,
		{ 0, 0, 0 },
		&asn_DFL_6_cmp_15,	/* Compare DEFAULT 15 */
		&asn_DFL_6_set_15,	/* Set DEFAULT 15 */
		"q-OffsetFreq-r13"
		},
	{ ATF_POINTER, 5, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, interFreqNeighCellList_r13),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_InterFreqNeighCellList_NB_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interFreqNeighCellList-r13"
		},
	{ ATF_POINTER, 4, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, interFreqBlackCellList_r13),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_InterFreqBlackCellList_NB_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"interFreqBlackCellList-r13"
		},
	{ ATF_POINTER, 3, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, multiBandInfoList_r13),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_MultiBandInfoList_NB_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"multiBandInfoList-r13"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, ext1),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		0,
		&asn_DEF_LTE_ext1_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext1"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, ext2),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		0,
		&asn_DEF_LTE_ext2_13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext2"
		},
};
static const int asn_MAP_LTE_InterFreqCarrierFreqInfo_NB_r13_oms_1[] = { 2, 3, 4, 5, 6, 7, 8, 9 };
static const ber_tlv_tag_t asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_InterFreqCarrierFreqInfo_NB_r13_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-CarrierFreq-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* q-RxLevMin-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* q-QualMin-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* p-Max-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* q-OffsetFreq-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* interFreqNeighCellList-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* interFreqBlackCellList-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* multiBandInfoList-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* ext1 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 } /* ext2 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_InterFreqCarrierFreqInfo_NB_r13_specs_1 = {
	sizeof(struct LTE_InterFreqCarrierFreqInfo_NB_r13),
	offsetof(struct LTE_InterFreqCarrierFreqInfo_NB_r13, _asn_ctx),
	asn_MAP_LTE_InterFreqCarrierFreqInfo_NB_r13_tag2el_1,
	10,	/* Count of tags in the map */
	asn_MAP_LTE_InterFreqCarrierFreqInfo_NB_r13_oms_1,	/* Optional members */
	6, 2,	/* Root/Additions */
	8,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13 = {
	"InterFreqCarrierFreqInfo-NB-r13",
	"InterFreqCarrierFreqInfo-NB-r13",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13_tags_1,
	sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13_tags_1)
		/sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13_tags_1[0]), /* 1 */
	asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13_tags_1)
		/sizeof(asn_DEF_LTE_InterFreqCarrierFreqInfo_NB_r13_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_InterFreqCarrierFreqInfo_NB_r13_1,
	10,	/* Elements count */
	&asn_SPC_LTE_InterFreqCarrierFreqInfo_NB_r13_specs_1	/* Additional specs */
};

