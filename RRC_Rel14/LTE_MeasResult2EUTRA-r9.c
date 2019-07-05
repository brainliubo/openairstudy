/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_MeasResult2EUTRA-r9.h"

asn_TYPE_member_t asn_MBR_LTE_MeasResult2EUTRA_r9_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_MeasResult2EUTRA_r9, carrierFreq_r9),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_ARFCN_ValueEUTRA,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"carrierFreq-r9"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_MeasResult2EUTRA_r9, measResultList_r9),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_MeasResultListEUTRA,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measResultList-r9"
		},
};
static const ber_tlv_tag_t asn_DEF_LTE_MeasResult2EUTRA_r9_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_MeasResult2EUTRA_r9_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* carrierFreq-r9 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* measResultList-r9 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_MeasResult2EUTRA_r9_specs_1 = {
	sizeof(struct LTE_MeasResult2EUTRA_r9),
	offsetof(struct LTE_MeasResult2EUTRA_r9, _asn_ctx),
	asn_MAP_LTE_MeasResult2EUTRA_r9_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_MeasResult2EUTRA_r9 = {
	"MeasResult2EUTRA-r9",
	"MeasResult2EUTRA-r9",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_MeasResult2EUTRA_r9_tags_1,
	sizeof(asn_DEF_LTE_MeasResult2EUTRA_r9_tags_1)
		/sizeof(asn_DEF_LTE_MeasResult2EUTRA_r9_tags_1[0]), /* 1 */
	asn_DEF_LTE_MeasResult2EUTRA_r9_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_MeasResult2EUTRA_r9_tags_1)
		/sizeof(asn_DEF_LTE_MeasResult2EUTRA_r9_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_MeasResult2EUTRA_r9_1,
	2,	/* Elements count */
	&asn_SPC_LTE_MeasResult2EUTRA_r9_specs_1	/* Additional specs */
};

