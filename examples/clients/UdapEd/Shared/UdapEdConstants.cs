namespace UdapEd.Shared;

public static class UdapEdConstants
{
    public const string CLIENT_CERTIFICATE_WITH_KEY = "clientCertificateWithKey";
    public const string CLIENT_CERTIFICATE = "clientCertificate";
    public const string ANCHOR_CERTIFICATE = "anchorCertificate";
    public const string CLIENT_NAME = "FhirLabs UdapEd";

    public const string TOKEN = "Token";
    public const string BASE_URL = "BaseUrl";
    public const string CLIENT_HEADERS = "ClientHeaders";

    /// <summary>
    /// See <a href="https://www.hl7.org/fhir/patient-operation-match.html">Patient-match</a>
    /// Canonical URL:: https://www.hl7.org/fhir/patient-operation-match.html
    ///
    /// The following are the defined In Parameter names from the Patient-match operation
    /// </summary>
    public static class PatientMatch
    {

        public static class InParameterNames
        {
            /// <summary>
            /// Note: One and only one resource where the name of the Parameter is "resource"
            /// </summary>
            public const string RESOURCE = "resource";

            public const string ONLY_CERTAIN_MATCHES = "onlyCertainMatches";

            public const string COUNT = "count";
        }

        public static class OutParameterNames
        {
            public const string SEARCH = "search";
        }
    }
}