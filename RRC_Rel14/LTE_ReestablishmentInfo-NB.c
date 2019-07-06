/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-InterNodeDefinitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_ReestablishmentInfo-NB.h"

asn_TYPE_member_t asn_MBR_LTE_ReestablishmentInfo_NB_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_ReestablishmentInfo_NB, sourcePhysCellId_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_PhysCellId,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sourcePhysCellId-r13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_ReestablishmentInfo_NB, targetCellShortMAC_I_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ShortMAC_I,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"targetCellShortMAC-I-r13"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_ReestablishmentInfo_NB, additionalReestabInfoList_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_AdditionalReestabInfoList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"additionalReestabInfoList-r13"
		},
};
static const int asn_MAP_LTE_ReestablishmentInfo_NB_oms_1[] = { 2 };
static const ber_tlv_tag_t asn_DEF_LTE_ReestablishmentInfo_NB_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_ReestablishmentInfo_NB_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sourcePhysCellId-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* targetCellShortMAC-I-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* additionalReestabInfoList-r13 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_ReestablishmentInfo_NB_specs_1 = {
	sizeof(struct LTE_ReestablishmentInfo_NB),
	offsetof(struct LTE_ReestablishmentInfo_NB, _asn_ctx),
	asn_MAP_LTE_ReestablishmentInfo_NB_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_LTE_ReestablishmentInfo_NB_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_ReestablishmentInfo_NB = {
	"ReestablishmentInfo-NB",
	"ReestablishmentInfo-NB",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_ReestablishmentInfo_NB_tags_1,
	sizeof(asn_DEF_LTE_ReestablishmentInfo_NB_tags_1)
		/sizeof(asn_DEF_LTE_ReestablishmentInfo_NB_tags_1[0]), /* 1 */
	asn_DEF_LTE_ReestablishmentInfo_NB_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_ReestablishmentInfo_NB_tags_1)
		/sizeof(asn_DEF_LTE_ReestablishmentInfo_NB_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_ReestablishmentInfo_NB_1,
	3,	/* Elements count */
	&asn_SPC_LTE_ReestablishmentInfo_NB_specs_1	/* Additional specs */
};
