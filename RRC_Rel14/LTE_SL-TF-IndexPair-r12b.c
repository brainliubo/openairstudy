/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_SL-TF-IndexPair-r12b.h"

static int
memb_LTE_discSF_Index_r12b_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 209)) {
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
memb_LTE_discPRB_Index_r12b_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 49)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_LTE_discSF_Index_r12b_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  0,  209 }	/* (0..209) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_discPRB_Index_r12b_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 6,  6,  0,  49 }	/* (0..49) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_LTE_SL_TF_IndexPair_r12b_1[] = {
	{ ATF_POINTER, 2, offsetof(struct LTE_SL_TF_IndexPair_r12b, discSF_Index_r12b),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_discSF_Index_r12b_constr_2,  memb_LTE_discSF_Index_r12b_constraint_1 },
		0, 0, /* No default value */
		"discSF-Index-r12b"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_SL_TF_IndexPair_r12b, discPRB_Index_r12b),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_discPRB_Index_r12b_constr_3,  memb_LTE_discPRB_Index_r12b_constraint_1 },
		0, 0, /* No default value */
		"discPRB-Index-r12b"
		},
};
static const int asn_MAP_LTE_SL_TF_IndexPair_r12b_oms_1[] = { 0, 1 };
static const ber_tlv_tag_t asn_DEF_LTE_SL_TF_IndexPair_r12b_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_SL_TF_IndexPair_r12b_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* discSF-Index-r12b */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* discPRB-Index-r12b */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_SL_TF_IndexPair_r12b_specs_1 = {
	sizeof(struct LTE_SL_TF_IndexPair_r12b),
	offsetof(struct LTE_SL_TF_IndexPair_r12b, _asn_ctx),
	asn_MAP_LTE_SL_TF_IndexPair_r12b_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_LTE_SL_TF_IndexPair_r12b_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_SL_TF_IndexPair_r12b = {
	"SL-TF-IndexPair-r12b",
	"SL-TF-IndexPair-r12b",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_SL_TF_IndexPair_r12b_tags_1,
	sizeof(asn_DEF_LTE_SL_TF_IndexPair_r12b_tags_1)
		/sizeof(asn_DEF_LTE_SL_TF_IndexPair_r12b_tags_1[0]), /* 1 */
	asn_DEF_LTE_SL_TF_IndexPair_r12b_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_SL_TF_IndexPair_r12b_tags_1)
		/sizeof(asn_DEF_LTE_SL_TF_IndexPair_r12b_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_SL_TF_IndexPair_r12b_1,
	2,	/* Elements count */
	&asn_SPC_LTE_SL_TF_IndexPair_r12b_specs_1	/* Additional specs */
};

