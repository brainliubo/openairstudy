/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_CrossCarrierSchedulingConfig-r10.h"

static int
memb_LTE_pdsch_Start_r10_constraint_5(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 4)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_LTE_pdsch_Start_r10_constr_7 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (1..4) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_LTE_schedulingCellInfo_r10_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_LTE_own_r10_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10__own_r10, cif_Presence_r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cif-Presence-r10"
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_own_r10_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_own_r10_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* cif-Presence-r10 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_own_r10_specs_3 = {
	sizeof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10__own_r10),
	offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10__own_r10, _asn_ctx),
	asn_MAP_LTE_own_r10_tag2el_3,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_own_r10_3 = {
	"own-r10",
	"own-r10",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_own_r10_tags_3,
	sizeof(asn_DEF_LTE_own_r10_tags_3)
		/sizeof(asn_DEF_LTE_own_r10_tags_3[0]) - 1, /* 1 */
	asn_DEF_LTE_own_r10_tags_3,	/* Same as above */
	sizeof(asn_DEF_LTE_own_r10_tags_3)
		/sizeof(asn_DEF_LTE_own_r10_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_own_r10_3,
	1,	/* Elements count */
	&asn_SPC_LTE_own_r10_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_other_r10_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10__other_r10, schedulingCellId_r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ServCellIndex_r10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"schedulingCellId-r10"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10__other_r10, pdsch_Start_r10),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, &asn_PER_memb_LTE_pdsch_Start_r10_constr_7,  memb_LTE_pdsch_Start_r10_constraint_5 },
		0, 0, /* No default value */
		"pdsch-Start-r10"
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_other_r10_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_other_r10_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* schedulingCellId-r10 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* pdsch-Start-r10 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_other_r10_specs_5 = {
	sizeof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10__other_r10),
	offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10__other_r10, _asn_ctx),
	asn_MAP_LTE_other_r10_tag2el_5,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_other_r10_5 = {
	"other-r10",
	"other-r10",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_other_r10_tags_5,
	sizeof(asn_DEF_LTE_other_r10_tags_5)
		/sizeof(asn_DEF_LTE_other_r10_tags_5[0]) - 1, /* 1 */
	asn_DEF_LTE_other_r10_tags_5,	/* Same as above */
	sizeof(asn_DEF_LTE_other_r10_tags_5)
		/sizeof(asn_DEF_LTE_other_r10_tags_5[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_other_r10_5,
	2,	/* Elements count */
	&asn_SPC_LTE_other_r10_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LTE_schedulingCellInfo_r10_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10, choice.own_r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_LTE_own_r10_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"own-r10"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10, choice.other_r10),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_LTE_other_r10_5,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"other-r10"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_schedulingCellInfo_r10_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* own-r10 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* other-r10 */
};
static asn_CHOICE_specifics_t asn_SPC_LTE_schedulingCellInfo_r10_specs_2 = {
	sizeof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10),
	offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10, _asn_ctx),
	offsetof(struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10, present),
	sizeof(((struct LTE_CrossCarrierSchedulingConfig_r10__schedulingCellInfo_r10 *)0)->present),
	asn_MAP_LTE_schedulingCellInfo_r10_tag2el_2,
	2,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_schedulingCellInfo_r10_2 = {
	"schedulingCellInfo-r10",
	"schedulingCellInfo-r10",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, &asn_PER_type_LTE_schedulingCellInfo_r10_constr_2, CHOICE_constraint },
	asn_MBR_LTE_schedulingCellInfo_r10_2,
	2,	/* Elements count */
	&asn_SPC_LTE_schedulingCellInfo_r10_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_CrossCarrierSchedulingConfig_r10_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_CrossCarrierSchedulingConfig_r10, schedulingCellInfo_r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_schedulingCellInfo_r10_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"schedulingCellInfo-r10"
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_CrossCarrierSchedulingConfig_r10_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_CrossCarrierSchedulingConfig_r10_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* schedulingCellInfo-r10 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_CrossCarrierSchedulingConfig_r10_specs_1 = {
	sizeof(struct LTE_CrossCarrierSchedulingConfig_r10),
	offsetof(struct LTE_CrossCarrierSchedulingConfig_r10, _asn_ctx),
	asn_MAP_LTE_CrossCarrierSchedulingConfig_r10_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_CrossCarrierSchedulingConfig_r10 = {
	"CrossCarrierSchedulingConfig-r10",
	"CrossCarrierSchedulingConfig-r10",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_CrossCarrierSchedulingConfig_r10_tags_1,
	sizeof(asn_DEF_LTE_CrossCarrierSchedulingConfig_r10_tags_1)
		/sizeof(asn_DEF_LTE_CrossCarrierSchedulingConfig_r10_tags_1[0]), /* 1 */
	asn_DEF_LTE_CrossCarrierSchedulingConfig_r10_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_CrossCarrierSchedulingConfig_r10_tags_1)
		/sizeof(asn_DEF_LTE_CrossCarrierSchedulingConfig_r10_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_CrossCarrierSchedulingConfig_r10_1,
	1,	/* Elements count */
	&asn_SPC_LTE_CrossCarrierSchedulingConfig_r10_specs_1	/* Additional specs */
};

