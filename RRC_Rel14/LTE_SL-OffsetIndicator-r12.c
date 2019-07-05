/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_SL-OffsetIndicator-r12.h"

static int
memb_LTE_small_r12_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 319)) {
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
memb_LTE_large_r12_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 10239)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_LTE_small_r12_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 9,  9,  0,  319 }	/* (0..319) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_LTE_large_r12_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 14,  14,  0,  10239 }	/* (0..10239) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_per_constraints_t asn_PER_type_LTE_SL_OffsetIndicator_r12_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_LTE_SL_OffsetIndicator_r12_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_OffsetIndicator_r12, choice.small_r12),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_small_r12_constr_2,  memb_LTE_small_r12_constraint_1 },
		0, 0, /* No default value */
		"small-r12"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_SL_OffsetIndicator_r12, choice.large_r12),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_large_r12_constr_3,  memb_LTE_large_r12_constraint_1 },
		0, 0, /* No default value */
		"large-r12"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_SL_OffsetIndicator_r12_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* small-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* large-r12 */
};
asn_CHOICE_specifics_t asn_SPC_LTE_SL_OffsetIndicator_r12_specs_1 = {
	sizeof(struct LTE_SL_OffsetIndicator_r12),
	offsetof(struct LTE_SL_OffsetIndicator_r12, _asn_ctx),
	offsetof(struct LTE_SL_OffsetIndicator_r12, present),
	sizeof(((struct LTE_SL_OffsetIndicator_r12 *)0)->present),
	asn_MAP_LTE_SL_OffsetIndicator_r12_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_LTE_SL_OffsetIndicator_r12 = {
	"SL-OffsetIndicator-r12",
	"SL-OffsetIndicator-r12",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_SL_OffsetIndicator_r12_constr_1, CHOICE_constraint },
	asn_MBR_LTE_SL_OffsetIndicator_r12_1,
	2,	/* Elements count */
	&asn_SPC_LTE_SL_OffsetIndicator_r12_specs_1	/* Additional specs */
};

