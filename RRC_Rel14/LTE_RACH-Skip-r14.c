/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_RACH-Skip-r14.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_LTE_numberOfConfUL_Processes_r14_constraint_8(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 8)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_LTE_ul_StartSubframe_r14_constraint_8(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 9)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_LTE_ul_Grant_r14_constraint_8(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 16)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_LTE_targetTA_r14_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  4 }	/* (0..4) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_ul_SchedInterval_r14_constr_10 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_numberOfConfUL_Processes_r14_constr_9 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (1..8) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_ul_StartSubframe_r14_constr_14 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  9 }	/* (0..9) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_ul_Grant_r14_constr_15 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  16,  16 }	/* (SIZE(16..16)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_LTE_targetTA_r14_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__targetTA_r14, choice.ta0_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ta0-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__targetTA_r14, choice.mcg_PTAG_r14),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mcg-PTAG-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__targetTA_r14, choice.scg_PTAG_r14),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scg-PTAG-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__targetTA_r14, choice.mcg_STAG_r14),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_STAG_Id_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mcg-STAG-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__targetTA_r14, choice.scg_STAG_r14),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_STAG_Id_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scg-STAG-r14"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_targetTA_r14_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ta0-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* mcg-PTAG-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* scg-PTAG-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* mcg-STAG-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* scg-STAG-r14 */
};
static asn_CHOICE_specifics_t asn_SPC_LTE_targetTA_r14_specs_2 = {
	sizeof(struct LTE_RACH_Skip_r14__targetTA_r14),
	offsetof(struct LTE_RACH_Skip_r14__targetTA_r14, _asn_ctx),
	offsetof(struct LTE_RACH_Skip_r14__targetTA_r14, present),
	sizeof(((struct LTE_RACH_Skip_r14__targetTA_r14 *)0)->present),
	asn_MAP_LTE_targetTA_r14_tag2el_2,
	5,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_targetTA_r14_2 = {
	"targetTA-r14",
	"targetTA-r14",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_targetTA_r14_constr_2, CHOICE_constraint },
	asn_MBR_LTE_targetTA_r14_2,
	5,	/* Elements count */
	&asn_SPC_LTE_targetTA_r14_specs_2	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_LTE_ul_SchedInterval_r14_value2enum_10[] = {
	{ 0,	3,	"sf2" },
	{ 1,	3,	"sf5" },
	{ 2,	4,	"sf10" }
};
static const unsigned int asn_MAP_LTE_ul_SchedInterval_r14_enum2value_10[] = {
	2,	/* sf10(2) */
	0,	/* sf2(0) */
	1	/* sf5(1) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_ul_SchedInterval_r14_specs_10 = {
	asn_MAP_LTE_ul_SchedInterval_r14_value2enum_10,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_ul_SchedInterval_r14_enum2value_10,	/* N => "tag"; sorted by N */
	3,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_ul_SchedInterval_r14_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ul_SchedInterval_r14_10 = {
	"ul-SchedInterval-r14",
	"ul-SchedInterval-r14",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_ul_SchedInterval_r14_tags_10,
	sizeof(asn_DEF_LTE_ul_SchedInterval_r14_tags_10)
		/sizeof(asn_DEF_LTE_ul_SchedInterval_r14_tags_10[0]) - 1, /* 1 */
	asn_DEF_LTE_ul_SchedInterval_r14_tags_10,	/* Same as above */
	sizeof(asn_DEF_LTE_ul_SchedInterval_r14_tags_10)
		/sizeof(asn_DEF_LTE_ul_SchedInterval_r14_tags_10[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_ul_SchedInterval_r14_constr_10, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_ul_SchedInterval_r14_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ul_ConfigInfo_r14_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__ul_ConfigInfo_r14, numberOfConfUL_Processes_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_numberOfConfUL_Processes_r14_constr_9,  memb_LTE_numberOfConfUL_Processes_r14_constraint_8 },
		0, 0, /* No default value */
		"numberOfConfUL-Processes-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__ul_ConfigInfo_r14, ul_SchedInterval_r14),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ul_SchedInterval_r14_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-SchedInterval-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__ul_ConfigInfo_r14, ul_StartSubframe_r14),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_ul_StartSubframe_r14_constr_14,  memb_LTE_ul_StartSubframe_r14_constraint_8 },
		0, 0, /* No default value */
		"ul-StartSubframe-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14__ul_ConfigInfo_r14, ul_Grant_r14),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ 0, &asn_PER_memb_LTE_ul_Grant_r14_constr_15,  memb_LTE_ul_Grant_r14_constraint_8 },
		0, 0, /* No default value */
		"ul-Grant-r14"
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_ul_ConfigInfo_r14_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ul_ConfigInfo_r14_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* numberOfConfUL-Processes-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ul-SchedInterval-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* ul-StartSubframe-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* ul-Grant-r14 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ul_ConfigInfo_r14_specs_8 = {
	sizeof(struct LTE_RACH_Skip_r14__ul_ConfigInfo_r14),
	offsetof(struct LTE_RACH_Skip_r14__ul_ConfigInfo_r14, _asn_ctx),
	asn_MAP_LTE_ul_ConfigInfo_r14_tag2el_8,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ul_ConfigInfo_r14_8 = {
	"ul-ConfigInfo-r14",
	"ul-ConfigInfo-r14",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ul_ConfigInfo_r14_tags_8,
	sizeof(asn_DEF_LTE_ul_ConfigInfo_r14_tags_8)
		/sizeof(asn_DEF_LTE_ul_ConfigInfo_r14_tags_8[0]) - 1, /* 1 */
	asn_DEF_LTE_ul_ConfigInfo_r14_tags_8,	/* Same as above */
	sizeof(asn_DEF_LTE_ul_ConfigInfo_r14_tags_8)
		/sizeof(asn_DEF_LTE_ul_ConfigInfo_r14_tags_8[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ul_ConfigInfo_r14_8,
	4,	/* Elements count */
	&asn_SPC_LTE_ul_ConfigInfo_r14_specs_8	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_RACH_Skip_r14_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RACH_Skip_r14, targetTA_r14),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_targetTA_r14_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"targetTA-r14"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_RACH_Skip_r14, ul_ConfigInfo_r14),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_LTE_ul_ConfigInfo_r14_8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ul-ConfigInfo-r14"
		},
};
static const int asn_MAP_LTE_RACH_Skip_r14_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_LTE_RACH_Skip_r14_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_RACH_Skip_r14_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* targetTA-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ul-ConfigInfo-r14 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_RACH_Skip_r14_specs_1 = {
	sizeof(struct LTE_RACH_Skip_r14),
	offsetof(struct LTE_RACH_Skip_r14, _asn_ctx),
	asn_MAP_LTE_RACH_Skip_r14_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_LTE_RACH_Skip_r14_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_RACH_Skip_r14 = {
	"RACH-Skip-r14",
	"RACH-Skip-r14",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_RACH_Skip_r14_tags_1,
	sizeof(asn_DEF_LTE_RACH_Skip_r14_tags_1)
		/sizeof(asn_DEF_LTE_RACH_Skip_r14_tags_1[0]), /* 1 */
	asn_DEF_LTE_RACH_Skip_r14_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_RACH_Skip_r14_tags_1)
		/sizeof(asn_DEF_LTE_RACH_Skip_r14_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_RACH_Skip_r14_1,
	2,	/* Elements count */
	&asn_SPC_LTE_RACH_Skip_r14_specs_1	/* Additional specs */
};

