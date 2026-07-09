# Standard Operating Procedure (SOP): Exchange Purpose (XP) Implementation: Treatment

> **Version:** 2.0 (published July 8, 2026)
> **Effective Date:** August 3, 2026
> **Applicability:** QHINs, Participants, Subparticipants
> **Source:** [Treatment-XP-SOP-v2.0_7.1.2026_508.pdf](https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Treatment-XP-SOP-v2.0_7.1.2026_508.pdf) — © The Sequoia Project
>
> Markdown conversion of the official PDF for AI/reference use. The PDF is authoritative.

## 1 Common Agreement References

The requirements set forth in this Standard Operating Procedure (SOP) are for implementation, in addition to the terms and conditions found in the Framework Agreements, the Qualified Health Information Network® (QHIN™) Technical Framework (QTF), and applicable SOPs. The Trusted Exchange Framework and Common Agreement™ (TEFCA™) Cross Reference Resource identifies which SOPs provide additional detail on specific references from the Common Agreement.

All documents cited in this SOP can be found on the Recognized Coordinating Entity® (RCE®) website.

## 2 Definitions

Select terms used throughout this SOP are defined in this section for ease of reference. All capitalized terms used in this SOP have the respective meanings assigned to such term in the TEFCA Glossary.

**Covered Entity:** has the meaning assigned to such term at 45 CFR § 160.103.

**Health Care Provider:** meets the definition of such term in either 45 CFR § 171.102 or in the HIPAA Rules at 45 CFR § 160.103.

**Health Plan:** has the meaning assigned to such term at 45 CFR § 160.103.

**State:** any of the several States, the District of Columbia, Puerto Rico, the Virgin Islands, Guam, American Samoa, and the Northern Mariana Islands.

**Treatment:** has the meaning assigned to such term at 45 CFR § 164.501.[^1]

**XP Code:** the code used to identify the XP in any given transaction, as set forth in the applicable SOP(s).

[^1]: As of the effective date of this SOP, 45 CFR § 164.501 defines Treatment as the provision, coordination, or management of health care and related services by one or more health care providers, including the coordination or management of health care by a health care provider with a third party; consultation between health care providers relating to a patient; or the referral of a patient for health care from one health care provider to another.

## 3 Purpose

In addition to the Common Agreement, QTF, and applicable SOPs, this SOP identifies implementation specifications QHINs, Participants, and Subparticipants must follow when asserting the Treatment Exchange Purpose, including use of the T-TRTMNT XP Code. Nothing in this SOP modifies the terms and conditions related to Treatment, as enumerated in the Exchange Purposes (XPs) SOP.

To help health care providers maintain and improve the care they provide to patients[^2], HIPAA defines "Treatment" broadly to include the provision, coordination, or management of health care and related services by one or more health care providers. It likewise defines "Health Care Providers" broadly to include any person or organization who furnishes, bills, or is paid for health care in the normal course of business. TEFCA is committed to supporting all of these health care providers who are providing Treatment.

To help build trust within TEFCA, it is critical to clarify these broad definitions when QHINs, Participants, and Subparticipants are required to Respond to a Treatment Query because making a Response required gives a requestor broad, automated access to the patient records under the stewardship of each QHIN, Participant, and Subparticipant. This SOP details the circumstances under which QHINs, Participants, and Subparticipants are required to Respond to a Treatment Query.

This SOP includes specifications for two XP Codes that, when asserted, signify Treatment as the reason for the Query (the "Treatment XP Codes"). Specifications for the T-TREAT XP Code are enumerated in Section 4 and specifications for the T-TRTMNT XP Code are enumerated in Section 5. Section 6 and Section 7 includes transaction and RCE Directory Service requirements that apply to all Treatment XP Codes.

[^2]: This is consistent with the Office for Civil Rights preamble discussion at 65 FR 82626 in the HIPAA Privacy Rule which specifically defines Treatment broadly in support of activities that improve or maintain the health of a patient. This clarification is relevant in the context of preventive and care management activities carried out in value-based care and other circumstances.

## 4 T-TREAT XP Code

The requirements in this Section 4 apply to the T-TREAT XP Code. Requirements for using the T-TRTMNT XP Code are set forth in Section 5.

### 4.1 Who is eligible to use the T-TREAT XP Code?

a) Health Care Providers and their Delegates

### 4.2 Under what circumstances can the T-TREAT XP Code be used?

a) T-TREAT can only be used in connection with Treatment.

### 4.3 Who MUST Respond to a Query that uses the T-TREAT XP Code?

a) No one. Responding Nodes are not required to Respond to QHIN Queries that use the T-TREAT XP Code.

b) All Responding Nodes SHOULD Respond to Queries for the T-TREAT XP Code that contain the information specified in this SOP, in accordance with the Framework Agreements and Applicable Law.

### 4.4 What Required Information MUST be included in a Response to a Query that uses the T-TREAT XP Code?

a) There is no Required Information for Queries that use the T-TREAT XP Code.

## 5 T-TRTMNT XP Code

The requirements in Section 5 apply to the T-TRTMNT XP Code. Requirements for using the T-TREAT XP Code are set forth in Section 4.

### 5.1 Which entities are eligible to use the T-TRTMNT XP Code?

a) A vetted Covered Entity Health Care Provider or its Delegate are eligible to use the T-TRTMNT XP Code. Notwithstanding the foregoing, a Health Plan cannot be a Delegate of any QHIN, Participant, or Subparticipant for purposes of initiating a Query using the T-TRTMNT XP Code.

b) The Veterans Health Administration, the Department of War, the Indian Health Service, the National Oceanic and Atmospheric Administration, the Coast Guard, and other Government Health Care Entity(ies) are eligible to use the T-TRTMNT XP Code.

c) A Delegate is not eligible to submit a Query using T-TRTMNT if the Health Care Provider for whom it serves as a Delegate is not permitted to submit a Query for T-TRTMNT under the same circumstances.

d) A Child Entity that is not a Covered Entity Health Care Provider is not eligible to use the T-TRTMNT XP Code.

### 5.2 Under what circumstances can the T-TRTMNT XP Code be used?

a) T-TRTMNT can only be used by a Health Care Provider[^3] in connection with Treatment relating to a documented present or planned clinical event for an Individual who is the subject of the Query to identify, deliver, or follow-up on that specific Individual's care. Below are illustrative, non-exhaustive examples of the use of T-TRTMNT. In the examples (except example (viii)(consultation) and (ix)(receipt of a referral)), the Querying Health Care Provider shall have previously been selected by the Individual who is the subject of the Query to provide health care to such Individual or shall have been assigned to provide care to the Individual who is the subject of the Query pursuant to a care model that contractually (or similarly) establishes the Querying Health Care Provider's clinical accountability to provide health care to that Individual through attribution, enrollment, assignment, or other similar mechanisms.

   i. Synchronous (e.g., in-person visit, telehealth visit, phone call) or asynchronous (e.g., e-mail or text message) interaction between the Individual who is the subject of the Query and the Querying Health Care Provider where the interaction is documented in that Individual's medical record or care plan
   ii. Scheduled or unscheduled appointment or other interaction between the Individual who is the subject of the Query and the Querying Health Care Provider
   iii. Question or request sent to the Querying Health Care Provider by the Individual who is the subject of the Query (e.g., refill request)
   iv. Medication reconciliation or medication management for the Individual who is the subject of the Query (e.g., refill reminder)
   v. Following receipt by the Querying Health Care Provider of a notification of the admission to or discharge from a hospital or long-term care facility, or other transition of care for the Individual who is the subject of the Query
   vi. In preparation for or following a transition of care for the Individual who is the subject of the Query
   vii. Determination by the Querying Health Care Provider of the need for preventative, follow-up, care coordination, or condition management for the Individual who is the subject of the Query, with such determination to be noted in the patient's medical record or care plan
   viii. Consultation between the Querying Health Care Provider with another Health Care Provider about the Individual who is the subject of the Query
   ix. Receipt of a referral by the Querying Health Care Provider from another Health Care Provider for the Individual who is the subject of the Query
   x. Receipt by the Querying Health Care Provider (e.g., a pharmacy) of a valid prescription to be filled for the Individual who is the subject of the Query
   xi. Receipt of an order by the Querying Health Care Provider for the Individual who is the subject of the Query
   xii. Notification to the Individual who is the subject of the Query regarding the fact that the Individual has been attributed, enrolled, assigned to the Querying Health Care Provider such that the Querying Health Care Provider has clinical accountability to provide care to that Individual

b) T-TRTMNT cannot be used for a Query that does not meet the requirements of Sections 5.1 and 5.2(a) of this SOP. In addition, a Health Care Provider cannot use T-TRTMNT as the XP Code for a Query under the following circumstances:

   i. A Health Care Provider cannot submit a Query using T-TRTMNT if the Individual who is the subject of the Query has terminated or declined to establish a care relationship with the Health Care Provider submitting the Query.
   ii. A Health Care Provider cannot submit a Query using T-TRTMNT if the Health Care Provider no longer has clinical accountability for the care of the Individual who is the subject of the Query (e.g., the Individual has been removed from the Querying Health Care Provider's assignment/attribution list or the Health Care Provider no longer participates in the clinical accountability program).
   iii. A Health Care Provider cannot submit Queries using T-TRTMNT for multiple Individuals in rapid succession if the Queries are not connected to a documented present or planned clinical event for each Individual who is the subject of a Query and the information received in response to each Query is not used by the Health Care Provider to identify, deliver, or follow-up on that specific Individual's care.
   iv. A Health Care Provider cannot submit multiple Queries using T-TRTMNT for the same Individual in succession (e.g., same day or different days) if each such Query is not connected to a different documented present or planned clinical event for the Individual who is the subject of a Query, unless (a) (i) the Health Care Provider Queries for additional information not included in a prior Query, such as further results and findings, or information not available at time of the prior Query, such as final reports; (ii) the subsequent Query includes updated or corrected demographic information, or (iii) the Query is resubmitted following a technical error, timeout, or incomplete response; and (b) information received in response to the Query is used by the Health Care Provider to identify, deliver, or follow-up on that specific Individual's care.
   v. A Health Care Provider cannot submit a Query using T-TRTMNT to prepare a research protocol or for similar purposes preparatory to research.

c) Additional examples for Section 5.2(a) or 5.2(b) may be provided through guidance or educational documents issued by the RCE.

[^3]: For purposes of this section, the Health Care Provider submitting the Query includes the respective Health Care Provider or its Delegate, subject to Section 5.1 of this SOP. The Health Care Provider submitting the Query is referred to as the "Querying Health Care Provider."

### 5.3 Who MUST Respond to a Query that uses the T-TRTMNT XP Code?

a) All Responding Nodes that are operated by or associated with a Health Care Provider or its Delegate MUST Respond.[^4]

b) All Responding Nodes that are operated by or associated with an IAS Provider that supports Response and the Individual has chosen for the IAS Provider to Respond MUST Respond.

c) All Responding Nodes that are not required to Respond to QHIN Queries for the T-TRTMNT XP Code SHOULD Respond to QHIN Query Requests for the T-TRTMNT XP Code.

d) Notwithstanding anything herein to the contrary, a Responding Node is not required to Respond if any of the exceptions set forth in Section 4.5 of the Exchange Purposes SOP applies.

[^4]: The RCE, in consultation with the Governing Council, will monitor reported metrics on T-HCO and T-PYMNT, as well as participation by Health Plans in TEFCA Exchange, to establish a timeline for Responding Nodes operated by or associated with Health Plans or Delegates of Health Plan to be required to Respond to T-TRTMNT.

### 5.4 What Required Information MUST be included in a Response to a Query that uses the T-TRTMNT XP Code?

a) Required Information is specified in the Exchange Purposes (XPs) SOP.

## 6 Transaction Requirements

### 6.1 QHIN Query

a) The Query MUST specify the date range for the requested data.

b) Query Identifying Information

   i. The Query MUST include:

      1. the Health Care Provider's individual or organizational National Provider Identifier (NPI) and/or Tax Identification Number (TIN), as applicable; and
         - a. The NPI Attribute MUST be encoded in the SAML attributes with a FriendlyName of `NPI` and MUST be NameFormat `urn:oasis:names:tc:xspa:2.0:subject:npi`.
         - b. The TIN attribute MUST be encoded in the SAML attributes with a FriendlyName of `TIN` and MUST be NameFormat `urn:nhin:names:saml:tin`.
      2. the Individual's Member ID and/or Subscriber ID,[^5] if known, as additional patient identifiers in the Request.

[^5]: See the Health Insurance Information data class in USCDI v3 available at <https://www.healthit.gov/isa/united-states-core-data-interoperability-uscdi#uscdi-v3>.

### 6.2 FHIR Query

a) The Query MUST include, as part of the Authorization and Authentication flows in the FHIR Security IG[^6] OAuth `hl7-b2b` extension:

   i. the Health Care Provider's individual or organizational NPI and/or TIN, as applicable, appended to the Human readable name within `organization_name`;
   ii. the ResourceID of the Organization entry in the RCE Directory Service of the Health Care Provider as `organization_id`; and
   iii. the Individual's Member ID and/or Subscriber ID, if known, as additional patient identifiers in the Query Patient Resource. The member ID/subscriber ID `Patient.identifier` code MUST be of system `http://hl7.org/fhir/us/davinci-hrex/CodeSystem/hrex-temp` and code `umb`.

[^6]: Implementation Guide available at <https://hl7.org/fhir/us/udap-security/>.

## 7 RCE Directory Service Requirements for Treatment XP Codes

a) A Participant or Subparticipant that operates a Principal Node that initiates Queries for either Treatment XP Code MUST have appropriate NPIs populated in the RCE Directory Service for the corresponding Participant, Subparticipant, and Child Entries.

   i. Where the Participant or Subparticipant has a Type 2 NPI that is representative of its broader organization, regardless of whether that Type 2 NPI is used for claims submission, the QHIN MUST populate that Type 2 NPI for the applicable Participant or Subparticipant entry in the RCE Directory Service. The NPI MUST match the NPI used in the vetting process.
   ii. If the Participant or Subparticipant does not have a Type 2 NPI and used a Representative Child Entry's Type 2 NPI in the XP Vetting Process, the QHIN MUST populate that Type 2 NPI for the applicable Participant or Subparticipant entry in the RCE Directory Service.
      1. The corresponding Child Entry in the RCE Directory Service MUST also use that same Type 2 NPI.
   iii. If the Participant or Subparticipant does not have a Type 2 NPI, does not have any Child Entries that have a Type 2 NPI, and the Participant or Subparticipant was vetted using a Representative Individual Provider with a Type 1 NPI, and not a representative Type 2 NPI, the QHIN MUST populate that Type 1 NPI for the applicable Participant or Subparticipant entry in the RCE Directory Service. For the avoidance of doubt, the use of such Type 1 NPI does not permit the listing of an individual as a Participant, Subparticipant, or Child Entry. The QHIN must update the Type 1 NPI in the RCE Directory Service in the event the individual is no longer associated with the Participant or Subparticipant.
   iv. To the extent a Child Entry has a Type 2 NPI, the QHIN MUST populate that Type 2 NPI for the applicable Child Entry in the RCE Directory Service.
   v. If the Participant, Subparticipant, or any Child Entry of the Participant or Subparticipant 1) does not have any NPI or CLIA Number and 2) is initiating Queries for T-TREAT, then the Participant, Subparticipant, or Child Entry is not required to populate an NPI or CLIA Number in the RCE Directory Service.

## 8 Compliance Dates

| SOP Section Number | Compliance Requirement | Applicability | Compliance Date |
|---|---|---|---|
| 4-6 | Use of Treatment XP Codes | QHINs / Participants / Subparticipants | August 3, 2026 |
| 7 | NPI populated in the RCE Directory Service according to the requirements | QHINs | September 3, 2026 |

## 9 Version History

| Version | Publication Date | Section #(s) of Update |
|---|---|---|
| 1.0 | Released July 1, 2024 | All Sections |
| 1.1 | April 11, 2025 | All Sections — Aligned with Exchange Purposes (XPs) SOP Version 4.0 |
| 1.2 | January 16, 2026 | Section 5.4 — Aligned with Exchange Purposes (XPs) SOP Version 5.0 |
| 2.0 | July 8, 2026 | All Sections — Aligned with Exchange Purposes (XPs) SOP Version 5.1 |
