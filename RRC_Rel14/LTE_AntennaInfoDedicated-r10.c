/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_AntennaInfoDedicated-r10.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_per_constraints_t asn_PER_type_LTE_transmissionMode_r10_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  15 }	/* (0..15) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_setup_constr_22 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_ue_TransmitAntennaSelection_constr_20 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_LTE_transmissionMode_r10_value2enum_2[] = {
	{ 0,	3,	"tm1" },
	{ 1,	3,	"tm2" },
	{ 2,	3,	"tm3" },
	{ 3,	3,	"tm4" },
	{ 4,	3,	"tm5" },
	{ 5,	3,	"tm6" },
	{ 6,	3,	"tm7" },
	{ 7,	8,	"tm8-v920" },
	{ 8,	9,	"tm9-v1020" },
	{ 9,	10,	"tm10-v1130" },
	{ 10,	6,	"spare6" },
	{ 11,	6,	"spare5" },
	{ 12,	6,	"spare4" },
	{ 13,	6,	"spare3" },
	{ 14,	6,	"spare2" },
	{ 15,	6,	"spare1" }
};
static const unsigned int asn_MAP_LTE_transmissionMode_r10_enum2value_2[] = {
	15,	/* spare1(15) */
	14,	/* spare2(14) */
	13,	/* spare3(13) */
	12,	/* spare4(12) */
	11,	/* spare5(11) */
	10,	/* spare6(10) */
	0,	/* tm1(0) */
	9,	/* tm10-v1130(9) */
	1,	/* tm2(1) */
	2,	/* tm3(2) */
	3,	/* tm4(3) */
	4,	/* tm5(4) */
	5,	/* tm6(5) */
	6,	/* tm7(6) */
	7,	/* tm8-v920(7) */
	8	/* tm9-v1020(8) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_transmissionMode_r10_specs_2 = {
	asn_MAP_LTE_transmissionMode_r10_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_transmissionMode_r10_enum2value_2,	/* N => "tag"; sorted by N */
	16,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_transmissionMode_r10_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_transmissionMode_r10_2 = {
	"transmissionMode-r10",
	"transmissionMode-r10",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_transmissionMode_r10_tags_2,
	sizeof(asn_DEF_LTE_transmissionMode_r10_tags_2)
		/sizeof(asn_DEF_LTE_transmissionMode_r10_tags_2[0]) - 1, /* 1 */
	asn_DEF_LTE_transmissionMode_r10_tags_2,	/* Same as above */
	sizeof(asn_DEF_LTE_transmissionMode_r10_tags_2)
		/sizeof(asn_DEF_LTE_transmissionMode_r10_tags_2[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_transmissionMode_r10_constr_2, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_transmissionMode_r10_specs_2	/* Additional specs */
};

static const asn_INTEGER_enum_map_t asn_MAP_LTE_setup_value2enum_22[] = {
	{ 0,	10,	"closedLoop" },
	{ 1,	8,	"openLoop" }
};
static const unsigned int asn_MAP_LTE_setup_enum2value_22[] = {
	0,	/* closedLoop(0) */
	1	/* openLoop(1) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_setup_specs_22 = {
	asn_MAP_LTE_setup_value2enum_22,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_setup_enum2value_22,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_setup_tags_22[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_setup_22 = {
	"setup",
	"setup",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_setup_tags_22,
	sizeof(asn_DEF_LTE_setup_tags_22)
		/sizeof(asn_DEF_LTE_setup_tags_22[0]) - 1, /* 1 */
	asn_DEF_LTE_setup_tags_22,	/* Same as above */
	sizeof(asn_DEF_LTE_setup_tags_22)
		/sizeof(asn_DEF_LTE_setup_tags_22[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_setup_constr_22, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_setup_specs_22	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ue_TransmitAntennaSelection_20[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_AntennaInfoDedicated_r10__ue_TransmitAntennaSelection, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_AntennaInfoDedicated_r10__ue_TransmitAntennaSelection, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_setup_22,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ue_TransmitAntennaSelection_tag2el_20[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_LTE_ue_TransmitAntennaSelection_specs_20 = {
	sizeof(struct LTE_AntennaInfoDedicated_r10__ue_TransmitAntennaSelection),
	offsetof(struct LTE_AntennaInfoDedicated_r10__ue_TransmitAntennaSelection, _asn_ctx),
	offsetof(struct LTE_AntennaInfoDedicated_r10__ue_TransmitAntennaSelection, present),
	sizeof(((struct LTE_AntennaInfoDedicated_r10__ue_TransmitAntennaSelection *)0)->present),
	asn_MAP_LTE_ue_TransmitAntennaSelection_tag2el_20,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ue_TransmitAntennaSelection_20 = {
	"ue-TransmitAntennaSelection",
	"ue-TransmitAntennaSelection",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_ue_TransmitAntennaSelection_constr_20, CHOICE_constraint },
	asn_MBR_LTE_ue_TransmitAntennaSelection_20,
	2,	/* Elements count */
	&asn_SPC_LTE_ue_TransmitAntennaSelection_specs_20	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_AntennaInfoDedicated_r10_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_AntennaInfoDedicated_r10, transmissionMode_r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_transmissionMode_r10_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"transmissionMode-r10"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_AntennaInfoDedicated_r10, codebookSubsetRestriction_r10),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"codebookSubsetRestriction-r10"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_AntennaInfoDedicated_r10, ue_TransmitAntennaSelection),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_ue_TransmitAntennaSelection_20,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ue-TransmitAntennaSelection"
		},
};
static const int asn_MAP_LTE_AntennaInfoDedicated_r10_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_LTE_AntennaInfoDedicated_r10_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_AntennaInfoDedicated_r10_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* transmissionMode-r10 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* codebookSubsetRestriction-r10 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* ue-TransmitAntennaSelection */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_AntennaInfoDedicated_r10_specs_1 = {
	sizeof(struct LTE_AntennaInfoDedicated_r10),
	offsetof(struct LTE_AntennaInfoDedicated_r10, _asn_ctx),
	asn_MAP_LTE_AntennaInfoDedicated_r10_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_AntennaInfoDedicated_r10_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_AntennaInfoDedicated_r10 = {
	"AntennaInfoDedicated-r10",
	"AntennaInfoDedicated-r10",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_AntennaInfoDedicated_r10_tags_1,
	sizeof(asn_DEF_LTE_AntennaInfoDedicated_r10_tags_1)
		/sizeof(asn_DEF_LTE_AntennaInfoDedicated_r10_tags_1[0]), /* 1 */
	asn_DEF_LTE_AntennaInfoDedicated_r10_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_AntennaInfoDedicated_r10_tags_1)
		/sizeof(asn_DEF_LTE_AntennaInfoDedicated_r10_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_AntennaInfoDedicated_r10_1,
	3,	/* Elements count */
	&asn_SPC_LTE_AntennaInfoDedicated_r10_specs_1	/* Additional specs */
};

