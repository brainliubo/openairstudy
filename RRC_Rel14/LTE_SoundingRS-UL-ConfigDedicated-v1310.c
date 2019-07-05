/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_SoundingRS-UL-ConfigDedicated-v1310.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_LTE_transmissionComb_v1310_constraint_3(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 2 && value <= 3)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_LTE_cyclicShift_v1310_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_transmissionCombNum_r13_constr_10 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_transmissionComb_v1310_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  2,  3 }	/* (2..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_per_constraints_t asn_PER_type_LTE_SoundingRS_UL_ConfigDedicated_v1310_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_LTE_cyclicShift_v1310_value2enum_5[] = {
	{ 0,	3,	"cs8" },
	{ 1,	3,	"cs9" },
	{ 2,	4,	"cs10" },
	{ 3,	4,	"cs11" }
};
static const unsigned int asn_MAP_LTE_cyclicShift_v1310_enum2value_5[] = {
	2,	/* cs10(2) */
	3,	/* cs11(3) */
	0,	/* cs8(0) */
	1	/* cs9(1) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_cyclicShift_v1310_specs_5 = {
	asn_MAP_LTE_cyclicShift_v1310_value2enum_5,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_cyclicShift_v1310_enum2value_5,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_cyclicShift_v1310_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_cyclicShift_v1310_5 = {
	"cyclicShift-v1310",
	"cyclicShift-v1310",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_cyclicShift_v1310_tags_5,
	sizeof(asn_DEF_LTE_cyclicShift_v1310_tags_5)
		/sizeof(asn_DEF_LTE_cyclicShift_v1310_tags_5[0]) - 1, /* 1 */
	asn_DEF_LTE_cyclicShift_v1310_tags_5,	/* Same as above */
	sizeof(asn_DEF_LTE_cyclicShift_v1310_tags_5)
		/sizeof(asn_DEF_LTE_cyclicShift_v1310_tags_5[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_cyclicShift_v1310_constr_5, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_cyclicShift_v1310_specs_5	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_LTE_transmissionCombNum_r13_value2enum_10[] = {
	{ 0,	2,	"n2" },
	{ 1,	2,	"n4" }
};
static const unsigned int asn_MAP_LTE_transmissionCombNum_r13_enum2value_10[] = {
	0,	/* n2(0) */
	1	/* n4(1) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_transmissionCombNum_r13_specs_10 = {
	asn_MAP_LTE_transmissionCombNum_r13_value2enum_10,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_transmissionCombNum_r13_enum2value_10,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_transmissionCombNum_r13_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_transmissionCombNum_r13_10 = {
	"transmissionCombNum-r13",
	"transmissionCombNum-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_transmissionCombNum_r13_tags_10,
	sizeof(asn_DEF_LTE_transmissionCombNum_r13_tags_10)
		/sizeof(asn_DEF_LTE_transmissionCombNum_r13_tags_10[0]) - 1, /* 1 */
	asn_DEF_LTE_transmissionCombNum_r13_tags_10,	/* Same as above */
	sizeof(asn_DEF_LTE_transmissionCombNum_r13_tags_10)
		/sizeof(asn_DEF_LTE_transmissionCombNum_r13_tags_10[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_transmissionCombNum_r13_constr_10, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_transmissionCombNum_r13_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_setup_3[] = {
	{ ATF_POINTER, 3, offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310__setup, transmissionComb_v1310),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_transmissionComb_v1310_constr_4,  memb_LTE_transmissionComb_v1310_constraint_3 },
		0, 0, /* No default value */
		"transmissionComb-v1310"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310__setup, cyclicShift_v1310),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_cyclicShift_v1310_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cyclicShift-v1310"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310__setup, transmissionCombNum_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_transmissionCombNum_r13_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transmissionCombNum-r13"
		},
};
static const int asn_MAP_LTE_setup_oms_3[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_LTE_setup_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_setup_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* transmissionComb-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cyclicShift-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* transmissionCombNum-r13 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_setup_specs_3 = {
	sizeof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310__setup),
	offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310__setup, _asn_ctx),
	asn_MAP_LTE_setup_tag2el_3,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_setup_oms_3,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_setup_3 = {
	"setup",
	"setup",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_setup_tags_3,
	sizeof(asn_DEF_LTE_setup_tags_3)
		/sizeof(asn_DEF_LTE_setup_tags_3[0]) - 1, /* 1 */
	asn_DEF_LTE_setup_tags_3,	/* Same as above */
	sizeof(asn_DEF_LTE_setup_tags_3)
		/sizeof(asn_DEF_LTE_setup_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_setup_3,
	3,	/* Elements count */
	&asn_SPC_LTE_setup_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_SoundingRS_UL_ConfigDedicated_v1310_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_LTE_setup_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_SoundingRS_UL_ConfigDedicated_v1310_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
asn_CHOICE_specifics_t asn_SPC_LTE_SoundingRS_UL_ConfigDedicated_v1310_specs_1 = {
	sizeof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310),
	offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310, _asn_ctx),
	offsetof(struct LTE_SoundingRS_UL_ConfigDedicated_v1310, present),
	sizeof(((struct LTE_SoundingRS_UL_ConfigDedicated_v1310 *)0)->present),
	asn_MAP_LTE_SoundingRS_UL_ConfigDedicated_v1310_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_LTE_SoundingRS_UL_ConfigDedicated_v1310 = {
	"SoundingRS-UL-ConfigDedicated-v1310",
	"SoundingRS-UL-ConfigDedicated-v1310",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_SoundingRS_UL_ConfigDedicated_v1310_constr_1, CHOICE_constraint },
	asn_MBR_LTE_SoundingRS_UL_ConfigDedicated_v1310_1,
	2,	/* Elements count */
	&asn_SPC_LTE_SoundingRS_UL_ConfigDedicated_v1310_specs_1	/* Additional specs */
};

