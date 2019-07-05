/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-UE-Variables"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_VarLogMeasConfig-r10.h"

static asn_TYPE_member_t asn_MBR_LTE_VarLogMeasConfig_r10_1[] = {
	{ ATF_POINTER, 1, offsetof(struct LTE_VarLogMeasConfig_r10, areaConfiguration_r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_LTE_AreaConfiguration_r10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"areaConfiguration-r10"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_VarLogMeasConfig_r10, loggingDuration_r10),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_LoggingDuration_r10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"loggingDuration-r10"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_VarLogMeasConfig_r10, loggingInterval_r10),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_LoggingInterval_r10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"loggingInterval-r10"
		},
};
static const int asn_MAP_LTE_VarLogMeasConfig_r10_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_LTE_VarLogMeasConfig_r10_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_VarLogMeasConfig_r10_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* areaConfiguration-r10 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* loggingDuration-r10 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* loggingInterval-r10 */
};
static asn_SEQUENCE_specifics_t asn_SPC_LTE_VarLogMeasConfig_r10_specs_1 = {
	sizeof(struct LTE_VarLogMeasConfig_r10),
	offsetof(struct LTE_VarLogMeasConfig_r10, _asn_ctx),
	asn_MAP_LTE_VarLogMeasConfig_r10_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_VarLogMeasConfig_r10_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_VarLogMeasConfig_r10 = {
	"VarLogMeasConfig-r10",
	"VarLogMeasConfig-r10",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_VarLogMeasConfig_r10_tags_1,
	sizeof(asn_DEF_LTE_VarLogMeasConfig_r10_tags_1)
		/sizeof(asn_DEF_LTE_VarLogMeasConfig_r10_tags_1[0]), /* 1 */
	asn_DEF_LTE_VarLogMeasConfig_r10_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_VarLogMeasConfig_r10_tags_1)
		/sizeof(asn_DEF_LTE_VarLogMeasConfig_r10_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_VarLogMeasConfig_r10_1,
	3,	/* Elements count */
	&asn_SPC_LTE_VarLogMeasConfig_r10_specs_1	/* Additional specs */
};

