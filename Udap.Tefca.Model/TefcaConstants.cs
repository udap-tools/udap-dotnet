#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Tefca.Model;

/// <summary>
/// Constants specific to the TEFCA trust community profile.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf">SOP: Facilitated FHIR Implementation v2.0</a>
/// </summary>
public static class TefcaConstants
{
    public static class UdapAuthorizationExtensions
    {
        /// <summary>
        /// TEFCA IAS Authorization Extension Object key name.
        ///
        /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">SOP v2.0 — Section 6.11 IAS, Table 4</a>
        /// </summary>
        public const string TEFCAIAS = "tefca-ias";

    }

    /// <summary>
    /// Field name constants for the TEFCA IAS Authorization Extension Object.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">SOP v2.0 — Section 6.11 IAS, Table 4</a>
    /// </summary>
    public static class TEFCAIASAuthorizationExtension
    {
        /// <summary>Fixed string value: "1". <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">Table 4</a></summary>
        public const string Version = "version";
        /// <summary>FHIR RelatedPerson Resource with all known demographics. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">Table 4</a></summary>
        public const string UserInformation = "user_information";
        /// <summary>FHIR US Core Patient Resource with all known demographics. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">Table 4</a></summary>
        public const string PatientInformation = "patient_information";
        /// <summary>Access Consent Policy Identifier for identity proofing level of assurance. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=17">Table 4</a></summary>
        public const string ConsentPolicy = "consent_policy";
        /// <summary>Array of FHIR DocumentReference or Consent resource URLs. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=17">Table 4</a></summary>
        public const string ConsentReference = "consent_reference";
        /// <summary>The CSP-provided OpenID Connect token. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=16">Table 4</a></summary>
        public const string IdToken = "id_token";
    }

    /// <summary>
    /// TEFCA Exchange Purpose (XP) codes OID: 2.16.840.1.113883.3.7204.1.5.2.1
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2025/01/SOP-Exchange-Purposes_CA-v2_v4-508.pdf#page=4">SOP: Exchange Purposes (XPs) v4.0 — Table 1</a>
    /// </summary>
    public static class ExchangePurposeCodes
    {
        public const string Oid = "2.16.840.1.113883.3.7204.1.5.2.1";

        public const string Treatment = "T-TREAT";
        public const string TefcaRequiredTreatment = "T-TRTMNT";
        public const string Payment = "T-PYMNT";
        public const string HealthCareOperations = "T-HCO";
        public const string CareCoordination = "T-HCO-CC";
        public const string HedisReporting = "T-HCO-HED";
        public const string QualityMeasureReporting = "T-HCO-QM";
        public const string PublicHealth = "T-PH";
        public const string ElectronicCaseReporting = "T-PH-ECR";
        public const string ElectronicLabReporting = "T-PH-ELR";
        public const string IndividualAccessServices = "T-IAS";
        public const string GovernmentBenefitsDetermination = "T-GOVDTRM";
    }

    /// <summary>
    /// TEFCA certification constants.
    ///
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">SOP v2.0 — Section 6.11 Registration #6</a>
    /// </summary>
    public static class Certification
    {
        /// <summary>URI identifying the TEFCA Basic App Certification program. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">Section 6.11 #2, #3</a></summary>
        public const string BasicAppCertificationUri = "https://rce.sequoiaproject.org/udap/profiles/basic-app-certification";
        /// <summary>Fixed certification_name value. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">Section 6.11 Registration #6</a></summary>
        public const string BasicAppCertificationName = "TEFCA Basic App Certification";
        /// <summary>Array of one Exchange Purpose from the TEFCA Exchange Purposes SOP. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">Section 6.11 Registration #6</a></summary>
        public const string ExchangePurposes = "exchange_purposes";
        /// <summary>HomeCommunityId of the Node making the registration request. <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=14">Section 6.11 Registration #6</a></summary>
        public const string HomeCommunityId = "home_community_id";
    }

    /// <summary>
    /// TEFCA community URI used in UDAP metadata discovery.
    /// </summary>
    public const string CommunityUri = "urn:oid:2.16.840.1.113883.3.7204.1.5";
}
