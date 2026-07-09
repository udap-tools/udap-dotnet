# Standard Operating Procedure (SOP): Exchange Purposes (XPs)

> **Version:** 5.1 (published July 8, 2026)
> **Effective Date:** August 3, 2026
> **Applicability:** QHINs, Participants, Subparticipants
> **Source:** [Exchange-Purposes-SOP-v5.1_7.1.2026_508.pdf](https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Exchange-Purposes-SOP-v5.1_7.1.2026_508.pdf) — © 2025 The Sequoia Project
>
> Markdown conversion of the official PDF for AI/reference use. The PDF is authoritative.

## 1 Common Agreement References

The requirements set forth in this Standard Operating Procedure (SOP) are for implementation, in addition to the terms and conditions found in the Framework Agreements, the Qualified Health Information Network® (QHIN™) Technical Framework (QTF), and applicable SOPs. The Trusted Exchange Framework and Common Agreement™ (TEFCA™) Cross Reference Resource identifies which SOPs provide additional detail on specific references from the Common Agreement.

All documents cited in this SOP can be found on the Recognized Coordinating Entity® (RCE®) website.

## 2 Definitions

Select terms used throughout this SOP are defined in this Section for ease of reference. All capitalized terms used in this SOP have the respective meanings assigned to such term in the TEFCA Glossary.

**Delegate:** a First Tier Delegate or Downstream Delegate.

**Downstream Delegate:** a QHIN, Participant, or Subparticipant that (i) is not acting as a Principal when initiating or Responding to a transaction via TEFCA Exchange and (ii) has a direct written agreement with a First Tier Delegate or another Downstream Delegate authorizing the respective Downstream Delegate to initiate or Respond to transactions via TEFCA Exchange for or on behalf of a Principal.

**First Tier Delegate:** a QHIN, Participant, or Subparticipant that (i) is not acting as a Principal when initiating or Responding to a transaction via TEFCA Exchange and (ii) has a direct written agreement with a Principal authorizing the First Tier Delegate to initiate or Respond to transactions via TEFCA Exchange for or on behalf of the Principal. For purposes of this definition, a "written agreement" shall be deemed to include a documented grant of authority from a government agency.

**Government Benefits Determination:** a determination made by any agency, instrumentality, or other unit of the federal, State, local, or tribal government as to whether an Individual qualifies for government benefits for any purpose other than health care (e.g., Social Security disability benefits) to the extent permitted by Applicable Law. Disclosure of TEFCA Information (TI) for this purpose may require an authorization that complies with Applicable Law.

**Health Care Operations:** has the meaning assigned to such term at 45 CFR § 164.501, except that this term shall apply to the applicable activities of a Health Care Provider regardless of whether the Health Care Provider is a HIPAA Covered Entity.

**Individual Access Services:** the services provided to an Individual by a QHIN, Participant, or Subparticipant that has a direct contractual relationship with such Individual in which the QHIN, Participant, or Subparticipant, as applicable, agrees to satisfy that Individual's ability to use TEFCA Exchange to access, inspect, obtain, or transmit a copy of that Individual's Required Information.

**Non-Required XP Code:** each XP Code that does not require a Response pursuant to this SOP.

**Payment:** has the meaning assigned to such term at 45 CFR § 164.501.

**Principal:** a QHIN, Participant or Subparticipant that is acting as a Covered Entity, Government Health Care Entity, NHE Health Care Provider, a Public Health Authority, a government agency that makes a Government Benefits Determination, or an IAS Provider (as authorized by an Individual) when engaging in TEFCA Exchange.

**Public Health Authority:** has the meaning assigned to such term at 45 CFR § 164.501.

**Public Health:** a Request, Use, Disclosure, or Response permitted under the HIPAA Rules and other Applicable Law for public health activities and purposes involving a Public Health Authority, where such public health activities and purposes are permitted by Applicable Law, including a Use or Disclosure permitted under 45 CFR § 164.512(b) and 45 CFR § 164.514. For the avoidance of doubt, a Public Health Authority may Request, Use, and Disclose TEFCA Information (TI) hereunder for Public Health to the extent permitted by Applicable Law and the Framework Agreements.

**Required Information:** the Electronic Health Information, as defined in 45 CFR § 171.102, that is (i) maintained in a Responding Node by any QHIN, Participant, or Subparticipant prior to or during the term of the applicable Framework Agreement and (ii) relevant for a required XP Code, as set forth in the QTF or an applicable SOP(s).

**Support:** the technical capability to receive and Respond to transactions from QHINs, Participants, and Subparticipants via TEFCA Exchange, including transmitting all information that a QHIN, Participant, or Subparticipant may send via TEFCA Exchange related to any XP Code (e.g., the content of the packet itself, if any).

**Treatment:** has the meaning set forth in 45 CFR § 164.501.[^1]

[^1]: As of the Effective Date of this SOP, 45 CFR § 164.501 defines Treatment as the provision, coordination, or management of health care and related services by one or more health care providers, including the coordination or management of health care by a health care provider with a third party; consultation between health care providers relating to a patient; or the referral of a patient for health care from one health care provider to another.

## 3 Purpose

The Common Agreement permits QHINs, Participants, and Subparticipants to utilize TEFCA Exchange only for authorized XPs. This Exchange Purposes (XPs) SOP defines the authorized XPs and identifies any XPs for which a response is required by a Responding Node pursuant to the Common Agreement, as well as when fees are prohibited or permitted. More information on implementation of each XP may be found in an XP Implementation SOP, as applicable.

## 4 Procedure

### 4.1 Authorized Exchange Purposes (XPs) and XP Codes

The authorized XPs are listed in Table 1. Each transaction initiated MUST be accompanied by the appropriate TEFCA XP Code in the table below. If there is a sub-XP Code that describes the reason for which an entity has initiated a QHIN Message Delivery or FHIR Push, then the entity MUST use the more specific sub-XP Code. If there is a sub-XP Code that describes the reason for which an entity has initiated a Query, then the entity MUST use the more specific sub-XP Code. For the avoidance of doubt, inclusion of an XP Code in the transaction is an attestation that the transaction adheres to the requirements in this SOP and/or an applicable XP Implementation SOP, as well as the Framework Agreements, the QHIN Technical Framework, and Applicable Law.

### 4.2 Required Response and Permitted Fees

a) Table 1 lists the XPs that require a Response per Section 9.4 of the Common Agreement.

b) Per Section 18.3 of the Common Agreement, QHINs, Participants, and Subparticipants that operate a Responding Node may charge fees to an Initiating Node when Responding to Queries through TEFCA Exchange, as permitted in Table 1 below and an applicable XP Implementation SOP. See Section 4.6 below for further details on how fees may be imposed between and among QHINs, Participants, and Subparticipants who choose to participate in TEFCA Exchange involving voluntary Non-Required XP Codes. Notwithstanding the foregoing and in accordance with Section 18.2 of the Common Agreement, if a QHIN is the Initiating Node, it may only reach an agreement on response fees with Participants or Subparticipants.

c) For purposes of this SOP, a Node is operated by the QHIN, Participant, or Subparticipant that signed the applicable Framework Agreement and is represented as the `organization.name` element in the RCE Directory Service for such Node.

d) Unless otherwise specified in an Exchange Purpose (XP) Implementation SOP, when a Responding Node is required to Respond to a Query for an XP Code, the Required Information for such Response is, at least, the USCDI v3.1 data classes and data elements that the Responding Node maintains. Additional specifications for Required Information are provided in the QTF.

   i. If the Responding Node is controlled by a Health Plan and required to Respond to a Query for an XP Code, the Required Information for such Response is, at least, the USCDI v3.1 data classes and data elements and any individual claims and encounter data (without provider remittances and enrollee cost-sharing information) that the Responding Node maintains.

### Table 1. XP Codes — Required Response and Permitted Fees

**XP Codes OID: `2.16.840.1.113883.3.7204.1.5.2.1`**

| Authorized XP | XP Code | Responding Node Response Obligations[^2] and Ability to Charge Fees (CA §18.3) |
|---|---|---|
| Treatment | `T-TREAT` | All Responding Nodes SHOULD Respond. No QHIN, Participant, or Subparticipant operating a Responding Node may charge fees to the Initiating Node for Responding. |
| Treatment | `T-TRTMNT` | All Responding Nodes that are operated by or associated[^3] with a Health Care Provider or its Delegate MUST Respond. All Responding Nodes that are operated by or associated with an IAS Provider that supports Response and the Individual has chosen for the IAS Provider to Respond. No QHIN, Participant, or Subparticipant operating a Responding Node may charge fees to the Initiating Node for Responding. |
| Payment | `T-PYMNT` | All Responding Nodes MAY Respond. A QHIN, Participant, or Subparticipant operating a Responding Node may charge fees to the Initiating Node for Responding. |
| Health Care Operations | `T-HCO` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Care Coordination/Case Management | `T-HCO-CC` | All Responding Nodes SHOULD Respond. Fees permitted. |
| HEDIS Reporting | `T-HCO-HED` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Quality Assessment and Improvement | `T-HCO-QAI` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Population-Based Activities | `T-HCO-POP` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Patient Safety | `T-HCO-PTSAFETY` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Performance Review | `T-HCO-PERF` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Public Health | `T-PH` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Electronic Case Reporting | `T-PH-ECR` | There are no Queries using this XP Code. It is message delivery/push-only. Fees permitted. |
| Electronic Lab Reporting | `T-PH-ELR` | There are no Queries using this XP Code. It is message delivery/push-only. Fees permitted. |
| Individual Access Services | `T-IAS` | All Responding Nodes MUST Respond. No QHIN, Participant, or Subparticipant operating a Responding Node may charge fees to the Initiating Node for Responding. |
| Government Benefits Determination | `T-GOVDTRM` | All Responding Nodes SHOULD Respond. Fees permitted. |
| Social Security Determination | `T-GOVDTRM-SSD` | Any Responding Node that has elected to use T-GOVDTRM-SSD and completed pre-coordination with SSA MUST Respond. SSA may compensate Responding Nodes in accordance with Applicable Law.[^4] |
| Access Consent Policy | `T-GOVDTRM-ACP` | Queries using this XP are only performed in conjunction with T-GOVDTRM-SSD. |

[^2]: More details on Query and Response obligations are in the respective authorized XP Implementation SOPs, if an XP Implementation SOP has been created. The Response obligations described in Table 1 apply to Queries that contain the information specified in the XP Implementation SOP, and all Responses must be in accordance with the Framework Agreements and Applicable Law.

[^3]: See the RCE Directory Services Policy SOP Sections 9-11 for more information on associated Responding Nodes.

[^4]: As per 75 FR 1446 Rate of Payment for Medical Records Received Through Health Information Technology (IT) Necessary To Make Disability Determinations, the Fees paid by the SSA for this use case are statutorily pre-determined. Sources responding to requests from the SSA shall be paid the fees outlined in 75 FR 1446. This notice may be updated from time to time by the Social Security Administration. This SOP does not modify the payments as outlined in 75 FR 1446 and does not interfere with fees or revenue sharing of fees between a responding Participant, Subparticipant or their QHIN. <https://www.federalregister.gov/documents/2010/01/11/2010-225/rate-of-payment-for-medical-records-received-through-health-information-technology-it-necessary-to>

### 4.3 Limitations on Types of Participants/Subparticipants

a) Initiating Nodes may only Query information for a specific XP if the Initiating Node is operated by a Principal that is the type of entity or person that is authorized by the Framework Agreements, applicable SOPs, and Applicable Law to assert Queries for that specific XP and such Query adheres to the requirements in this SOP and/or an applicable XP Implementation SOP.

b) Notwithstanding the foregoing, a Principal may use a Delegate to make such Query or transact for a specific XP, provided that the Principal has in place a Delegation Notice that authorizes the Delegate to make such Query or to transact for the specific XP. For the avoidance of doubt, the Delegate's use of the XP must adhere to all requirements in this SOP and/or an applicable XP Implementation SOP that apply to both the Delegate and the Principal for which it is initiating the transaction.

### 4.4 Required Support

a) QHINs MUST Support all the XP Codes.

b) Responding Nodes MUST Support any XP Code that they are required to Respond to per Table 1 of this SOP.

c) Responding Nodes MAY Support any XP Code that is authorized per Section 4.1 and Table 1 of this SOP.

### 4.5 Exceptions to Required Responses

a) The below are exceptions to the Response requirements set forth in this SOP.

   i. If the Response is prohibited by Applicable Law or is not in accordance with the Common Agreement;
   ii. If the Responding Node is operated by an IAS Provider and the Individual who is the subject of the Query has chosen for the IAS Provider to not make Disclosures in response to Queries via TEFCA Exchange;
   iii. If the Responding Node is operated by a Public Health Authority;
   iv. If the Responding Node is operated by a federal, State, local, or tribal agency, instrumentality, or other unit of government, including such government agency's Delegate(s), using TEFCA Exchange solely for purposes of requesting information for Government Benefits Determination;
   v. If the reason asserted for the Query is Individual Access Services and the information would not be required to be provided to an Individual pursuant to 45 CFR § 164.524(a)(2), regardless of whether the Responding Node is operated by a Non-HIPAA Entity, a Covered Entity, or a Business Associate;
   vi. If the Requested information is not Required Information;
   vii. If the Responding Node is operated by a federal agency, to the extent that the Requested Disclosure of Required Information is not permitted under Applicable Law (e.g., it is Controlled Unclassified Information as defined at 32 CFR Part 2002, and the party requesting it does not comply with the applicable policies and controls that the federal agency adopted to satisfy its requirements);
   viii. If the XP is authorized but not required at the time of the Query, either under this SOP, applicable XP Implementation SOPs, or the Common Agreement;
   ix. If the Responding Node is operated by a Delegate for which an Initiating Node Only Attestation Form has been submitted; or
   x. An applicable SOP exempts the Required Response.

### 4.6 Applicability of Section 6.2.2 of the Common Agreement and Section 2.2.2 of the Participant/Subparticipant Terms of Participation (ToP)

a) For all XP Codes that require a Response pursuant to this SOP, the non-discrimination provisions in Section 6.2.2 of the Common Agreement and Section 2.2.2 of the ToP shall apply.

b) For each Non-Required XP Code, Section 6.2.2 of the Common Agreement and Section 2.2.2 of the ToP shall not apply to TEFCA Exchange conducted for such Non-Required XP Code. For these Non-Required XP Codes, QHINs, Participants, and Subparticipants MAY determine their own exchange partners. When determining their own exchange partners, QHINs, Participants, and Subparticipants remain subject to all other applicable provisions of the Framework Agreements, SOPs, and QTF. Where the Framework Agreements, SOPs, or QTF do not address certain aspects of the exchange between the partners, the partners may agree upon those aspects to facilitate and support their exchange activities. These aspects include, but are not limited to, the following:

   i. Fees for Query responses and the terms and conditions associated with those fees;
   ii. The data that is needed by the initiator of the Query to fulfill the purpose of its Query and that will be returned by the Responding Node;
   iii. Service level agreements related to the frequency, timing or number of Queries and responses between the Initiating Node and Responding Node;
   iv. The patient population for which the Initiating Node will query the Responding Node; and/or
   v. Reciprocity requirements between the exchange partners.

c) On a monthly basis, QHINs will report to the RCE on metrics related to the exchange of data under Non-Required XP Codes. The RCE, in consultation with the Governing Council, or a group appointed by the Governing Council, will create a specifications document on what metrics must be reported to the RCE. The metrics could include, for example:

   i. Description of the use case,
   ii. Exchange partners involved,
   iii. Approximate traffic volumes and quantity of active participants per XP Code, and
   iv. Identification of any standards or technical specifications that the exchange partners are using.

   The RCE will use such information to, among other things, assist in evaluating whether it is appropriate to develop additional SOP requirements associated with the Non-Required XP Code or if a Response for such XP Code would make sense to be changed to required. Any conversion of a Non-Required XP Code to an XP Code for which Response is required and the timeline for implementing such a change will require an amendment to this SOP.

d) The Governing Council will evaluate Non-Required XP Codes exchange twice a year, during which review it may identify:

   i. Trends and exchange patterns; or
   ii. Recommended next steps, such as creating or updating a roadmap to Required Response or suggesting revisions to XP Implementation SOPs based on experience.

e) In February of 2028, the Governing Council will evaluate whether to re-introduce non-discrimination for certain Non-Required XPs based on the metrics reported.

f) Any Dispute related to the provisions of the Common Agreement, including any SOPs, the QHIN Technical Framework, and all other attachments, exhibits, and artifacts incorporated by reference will be resolved through the TEFCA Dispute Resolution Process. Any dispute about the terms agreed upon between exchange partners for the exchange of data under Non-Required XP Codes and that are not addressed by the Framework Agreements, SOPs, or QHIN Technical Framework must be handled between the exchange partners.

## 5 Version History

| Version | Publication Date | Section #(s) of Update |
|---|---|---|
| 1.0 | Released June 2022 | N/A |
| 2.0 | July 1, 2024 | All sections |
| 3.0 | August 6, 2024 | Table 1, Table 2, Section 4.2, Section 4.5 |
| 4.0 | January 16, 2025 | Section 4.1, removal of Table 1, change Table 2 to Table 1, addition of Section 4.7 |
| 4.1 | December 4, 2025 | Section 4.2, Table 1 |
| 5.0 | January 16, 2026 | Section 3, Section 4.1, Section 4.2, Table 1; Section 4.5; Section 4.6; Section 4.7 |
| 5.1 | July 8, 2026 | Section 4.2, Section 4.3, Table 1 |
