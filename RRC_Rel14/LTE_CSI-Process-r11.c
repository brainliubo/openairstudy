/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_CSI-Process-r11.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_LTE_setup_constraint_13(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 2)) {
		/* Perform validation of the inner elements */
		return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_LTE_cqi_ReportPeriodicProcId_r11_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 3)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_LTE_alternativeCodebookEnabledFor4TXProc_r12_constr_11 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_setup_constr_15 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 1,  1,  1,  2 }	/* (SIZE(1..2)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_setup_constr_15 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 1,  1,  1,  2 }	/* (SIZE(1..2)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_csi_IM_ConfigIdList_r12_constr_13 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_cqi_ReportAperiodicProc2_r12_constr_17 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_cqi_ReportAperiodicProc_v1310_constr_21 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_cqi_ReportAperiodicProc2_v1310_constr_24 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_cqi_ReportPeriodicProcId_r11_constr_7 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_LTE_alternativeCodebookEnabledFor4TXProc_r12_value2enum_11[] = {
	{ 0,	4,	"true" }
};
static const unsigned int asn_MAP_LTE_alternativeCodebookEnabledFor4TXProc_r12_enum2value_11[] = {
	0	/* true(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_alternativeCodebookEnabledFor4TXProc_r12_specs_11 = {
	asn_MAP_LTE_alternativeCodebookEnabledFor4TXProc_r12_value2enum_11,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_alternativeCodebookEnabledFor4TXProc_r12_enum2value_11,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_11 = {
	"alternativeCodebookEnabledFor4TXProc-r12",
	"alternativeCodebookEnabledFor4TXProc-r12",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_tags_11,
	sizeof(asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_tags_11)
		/sizeof(asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_tags_11[0]) - 1, /* 1 */
	asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_tags_11,	/* Same as above */
	sizeof(asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_tags_11)
		/sizeof(asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_tags_11[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_alternativeCodebookEnabledFor4TXProc_r12_constr_11, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_alternativeCodebookEnabledFor4TXProc_r12_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_setup_15[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_LTE_CSI_IM_ConfigId_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_setup_tags_15[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_LTE_setup_specs_15 = {
	sizeof(struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12__setup),
	offsetof(struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12__setup, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_setup_15 = {
	"setup",
	"setup",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_LTE_setup_tags_15,
	sizeof(asn_DEF_LTE_setup_tags_15)
		/sizeof(asn_DEF_LTE_setup_tags_15[0]) - 1, /* 1 */
	asn_DEF_LTE_setup_tags_15,	/* Same as above */
	sizeof(asn_DEF_LTE_setup_tags_15)
		/sizeof(asn_DEF_LTE_setup_tags_15[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_setup_constr_15, SEQUENCE_OF_constraint },
	asn_MBR_LTE_setup_15,
	1,	/* Single element */
	&asn_SPC_LTE_setup_specs_15	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_csi_IM_ConfigIdList_r12_13[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_LTE_setup_15,
		0,
		{ 0, &asn_PER_memb_LTE_setup_constr_15,  memb_LTE_setup_constraint_13 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_csi_IM_ConfigIdList_r12_tag2el_13[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_LTE_csi_IM_ConfigIdList_r12_specs_13 = {
	sizeof(struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12),
	offsetof(struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12, _asn_ctx),
	offsetof(struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12, present),
	sizeof(((struct LTE_CSI_Process_r11__ext1__csi_IM_ConfigIdList_r12 *)0)->present),
	asn_MAP_LTE_csi_IM_ConfigIdList_r12_tag2el_13,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_csi_IM_ConfigIdList_r12_13 = {
	"csi-IM-ConfigIdList-r12",
	"csi-IM-ConfigIdList-r12",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_csi_IM_ConfigIdList_r12_constr_13, CHOICE_constraint },
	asn_MBR_LTE_csi_IM_ConfigIdList_r12_13,
	2,	/* Elements count */
	&asn_SPC_LTE_csi_IM_ConfigIdList_r12_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_cqi_ReportAperiodicProc2_r12_17[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext1__cqi_ReportAperiodicProc2_r12, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext1__cqi_ReportAperiodicProc2_r12, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CQI_ReportAperiodicProc_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_cqi_ReportAperiodicProc2_r12_tag2el_17[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_LTE_cqi_ReportAperiodicProc2_r12_specs_17 = {
	sizeof(struct LTE_CSI_Process_r11__ext1__cqi_ReportAperiodicProc2_r12),
	offsetof(struct LTE_CSI_Process_r11__ext1__cqi_ReportAperiodicProc2_r12, _asn_ctx),
	offsetof(struct LTE_CSI_Process_r11__ext1__cqi_ReportAperiodicProc2_r12, present),
	sizeof(((struct LTE_CSI_Process_r11__ext1__cqi_ReportAperiodicProc2_r12 *)0)->present),
	asn_MAP_LTE_cqi_ReportAperiodicProc2_r12_tag2el_17,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_cqi_ReportAperiodicProc2_r12_17 = {
	"cqi-ReportAperiodicProc2-r12",
	"cqi-ReportAperiodicProc2-r12",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_cqi_ReportAperiodicProc2_r12_constr_17, CHOICE_constraint },
	asn_MBR_LTE_cqi_ReportAperiodicProc2_r12_17,
	2,	/* Elements count */
	&asn_SPC_LTE_cqi_ReportAperiodicProc2_r12_specs_17	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext1_10[] = {
	{ ATF_POINTER, 3, offsetof(struct LTE_CSI_Process_r11__ext1, alternativeCodebookEnabledFor4TXProc_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_alternativeCodebookEnabledFor4TXProc_r12_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"alternativeCodebookEnabledFor4TXProc-r12"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_CSI_Process_r11__ext1, csi_IM_ConfigIdList_r12),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_csi_IM_ConfigIdList_r12_13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"csi-IM-ConfigIdList-r12"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_CSI_Process_r11__ext1, cqi_ReportAperiodicProc2_r12),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_cqi_ReportAperiodicProc2_r12_17,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportAperiodicProc2-r12"
		},
};
static const int asn_MAP_LTE_ext1_oms_10[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_LTE_ext1_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext1_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* alternativeCodebookEnabledFor4TXProc-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* csi-IM-ConfigIdList-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* cqi-ReportAperiodicProc2-r12 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext1_specs_10 = {
	sizeof(struct LTE_CSI_Process_r11__ext1),
	offsetof(struct LTE_CSI_Process_r11__ext1, _asn_ctx),
	asn_MAP_LTE_ext1_tag2el_10,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_ext1_oms_10,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext1_10 = {
	"ext1",
	"ext1",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext1_tags_10,
	sizeof(asn_DEF_LTE_ext1_tags_10)
		/sizeof(asn_DEF_LTE_ext1_tags_10[0]) - 1, /* 1 */
	asn_DEF_LTE_ext1_tags_10,	/* Same as above */
	sizeof(asn_DEF_LTE_ext1_tags_10)
		/sizeof(asn_DEF_LTE_ext1_tags_10[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext1_10,
	3,	/* Elements count */
	&asn_SPC_LTE_ext1_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_cqi_ReportAperiodicProc_v1310_21[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc_v1310, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc_v1310, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CQI_ReportAperiodicProc_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_cqi_ReportAperiodicProc_v1310_tag2el_21[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_LTE_cqi_ReportAperiodicProc_v1310_specs_21 = {
	sizeof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc_v1310),
	offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc_v1310, _asn_ctx),
	offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc_v1310, present),
	sizeof(((struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc_v1310 *)0)->present),
	asn_MAP_LTE_cqi_ReportAperiodicProc_v1310_tag2el_21,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_cqi_ReportAperiodicProc_v1310_21 = {
	"cqi-ReportAperiodicProc-v1310",
	"cqi-ReportAperiodicProc-v1310",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_cqi_ReportAperiodicProc_v1310_constr_21, CHOICE_constraint },
	asn_MBR_LTE_cqi_ReportAperiodicProc_v1310_21,
	2,	/* Elements count */
	&asn_SPC_LTE_cqi_ReportAperiodicProc_v1310_specs_21	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_cqi_ReportAperiodicProc2_v1310_24[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc2_v1310, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"release"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc2_v1310, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CQI_ReportAperiodicProc_v1310,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"setup"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_cqi_ReportAperiodicProc2_v1310_tag2el_24[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* release */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* setup */
};
static asn_CHOICE_specifics_t asn_SPC_LTE_cqi_ReportAperiodicProc2_v1310_specs_24 = {
	sizeof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc2_v1310),
	offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc2_v1310, _asn_ctx),
	offsetof(struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc2_v1310, present),
	sizeof(((struct LTE_CSI_Process_r11__ext2__cqi_ReportAperiodicProc2_v1310 *)0)->present),
	asn_MAP_LTE_cqi_ReportAperiodicProc2_v1310_tag2el_24,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_cqi_ReportAperiodicProc2_v1310_24 = {
	"cqi-ReportAperiodicProc2-v1310",
	"cqi-ReportAperiodicProc2-v1310",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_cqi_ReportAperiodicProc2_v1310_constr_24, CHOICE_constraint },
	asn_MBR_LTE_cqi_ReportAperiodicProc2_v1310_24,
	2,	/* Elements count */
	&asn_SPC_LTE_cqi_ReportAperiodicProc2_v1310_specs_24	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext2_20[] = {
	{ ATF_POINTER, 3, offsetof(struct LTE_CSI_Process_r11__ext2, cqi_ReportAperiodicProc_v1310),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_cqi_ReportAperiodicProc_v1310_21,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportAperiodicProc-v1310"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_CSI_Process_r11__ext2, cqi_ReportAperiodicProc2_v1310),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_cqi_ReportAperiodicProc2_v1310_24,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportAperiodicProc2-v1310"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_CSI_Process_r11__ext2, eMIMO_Type_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_CSI_RS_ConfigEMIMO_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"eMIMO-Type-r13"
		},
};
static const int asn_MAP_LTE_ext2_oms_20[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_LTE_ext2_tags_20[] = {
	(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext2_tag2el_20[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cqi-ReportAperiodicProc-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cqi-ReportAperiodicProc2-v1310 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* eMIMO-Type-r13 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext2_specs_20 = {
	sizeof(struct LTE_CSI_Process_r11__ext2),
	offsetof(struct LTE_CSI_Process_r11__ext2, _asn_ctx),
	asn_MAP_LTE_ext2_tag2el_20,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_ext2_oms_20,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext2_20 = {
	"ext2",
	"ext2",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext2_tags_20,
	sizeof(asn_DEF_LTE_ext2_tags_20)
		/sizeof(asn_DEF_LTE_ext2_tags_20[0]) - 1, /* 1 */
	asn_DEF_LTE_ext2_tags_20,	/* Same as above */
	sizeof(asn_DEF_LTE_ext2_tags_20)
		/sizeof(asn_DEF_LTE_ext2_tags_20[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext2_20,
	3,	/* Elements count */
	&asn_SPC_LTE_ext2_specs_20	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_ext3_28[] = {
	{ ATF_POINTER, 3, offsetof(struct LTE_CSI_Process_r11__ext3, eMIMO_Type_v1430),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_CSI_RS_ConfigEMIMO_v1430,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"eMIMO-Type-v1430"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_CSI_Process_r11__ext3, eMIMO_Hybrid_r14),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_CSI_RS_ConfigEMIMO_Hybrid_r14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"eMIMO-Hybrid-r14"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_CSI_Process_r11__ext3, advancedCodebookEnabled_r14),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"advancedCodebookEnabled-r14"
		},
};
static const int asn_MAP_LTE_ext3_oms_28[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_LTE_ext3_tags_28[] = {
	(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ext3_tag2el_28[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* eMIMO-Type-v1430 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* eMIMO-Hybrid-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* advancedCodebookEnabled-r14 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_ext3_specs_28 = {
	sizeof(struct LTE_CSI_Process_r11__ext3),
	offsetof(struct LTE_CSI_Process_r11__ext3, _asn_ctx),
	asn_MAP_LTE_ext3_tag2el_28,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_ext3_oms_28,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_ext3_28 = {
	"ext3",
	"ext3",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ext3_tags_28,
	sizeof(asn_DEF_LTE_ext3_tags_28)
		/sizeof(asn_DEF_LTE_ext3_tags_28[0]) - 1, /* 1 */
	asn_DEF_LTE_ext3_tags_28,	/* Same as above */
	sizeof(asn_DEF_LTE_ext3_tags_28)
		/sizeof(asn_DEF_LTE_ext3_tags_28[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ext3_28,
	3,	/* Elements count */
	&asn_SPC_LTE_ext3_specs_28	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_CSI_Process_r11_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11, csi_ProcessId_r11),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CSI_ProcessId_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"csi-ProcessId-r11"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11, csi_RS_ConfigNZPId_r11),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CSI_RS_ConfigNZPId_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"csi-RS-ConfigNZPId-r11"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11, csi_IM_ConfigId_r11),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CSI_IM_ConfigId_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"csi-IM-ConfigId-r11"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CSI_Process_r11, p_C_AndCBSRList_r11),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_P_C_AndCBSR_Pair_r13a,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"p-C-AndCBSRList-r11"
		},
	{ ATF_POINTER, 6, offsetof(struct LTE_CSI_Process_r11, cqi_ReportBothProc_r11),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CQI_ReportBothProc_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportBothProc-r11"
		},
	{ ATF_POINTER, 5, offsetof(struct LTE_CSI_Process_r11, cqi_ReportPeriodicProcId_r11),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_cqi_ReportPeriodicProcId_r11_constr_7,  memb_LTE_cqi_ReportPeriodicProcId_r11_constraint_1 },
		0, 0, /* No default value */
		"cqi-ReportPeriodicProcId-r11"
		},
	{ ATF_POINTER, 4, offsetof(struct LTE_CSI_Process_r11, cqi_ReportAperiodicProc_r11),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CQI_ReportAperiodicProc_r11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cqi-ReportAperiodicProc-r11"
		},
	{ ATF_POINTER, 3, offsetof(struct LTE_CSI_Process_r11, ext1),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		0,
		&asn_DEF_LTE_ext1_10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext1"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_CSI_Process_r11, ext2),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		0,
		&asn_DEF_LTE_ext2_20,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext2"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_CSI_Process_r11, ext3),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		0,
		&asn_DEF_LTE_ext3_28,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"ext3"
		},
};
static const int asn_MAP_LTE_CSI_Process_r11_oms_1[] = { 4, 5, 6, 7, 8, 9 };
static const ber_tlv_tag_t asn_DEF_LTE_CSI_Process_r11_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_CSI_Process_r11_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* csi-ProcessId-r11 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* csi-RS-ConfigNZPId-r11 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* csi-IM-ConfigId-r11 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* p-C-AndCBSRList-r11 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* cqi-ReportBothProc-r11 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* cqi-ReportPeriodicProcId-r11 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* cqi-ReportAperiodicProc-r11 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* ext1 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* ext2 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 } /* ext3 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_CSI_Process_r11_specs_1 = {
	sizeof(struct LTE_CSI_Process_r11),
	offsetof(struct LTE_CSI_Process_r11, _asn_ctx),
	asn_MAP_LTE_CSI_Process_r11_tag2el_1,
	10,	/* Count of tags in the map */
	asn_MAP_LTE_CSI_Process_r11_oms_1,	/* Optional members */
	3, 3,	/* Root/Additions */
	7,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_CSI_Process_r11 = {
	"CSI-Process-r11",
	"CSI-Process-r11",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_CSI_Process_r11_tags_1,
	sizeof(asn_DEF_LTE_CSI_Process_r11_tags_1)
		/sizeof(asn_DEF_LTE_CSI_Process_r11_tags_1[0]), /* 1 */
	asn_DEF_LTE_CSI_Process_r11_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_CSI_Process_r11_tags_1)
		/sizeof(asn_DEF_LTE_CSI_Process_r11_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_CSI_Process_r11_1,
	10,	/* Elements count */
	&asn_SPC_LTE_CSI_Process_r11_specs_1	/* Additional specs */
};

