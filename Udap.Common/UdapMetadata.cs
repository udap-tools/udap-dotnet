#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;

namespace Udap.Common;

/// <summary>
/// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#required-udap-metadata">2.2 Required UDAP Metadata</a>
/// </summary>
public class UdapMetadata
{
    /// <summary>
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#required-udap-metadata">2.2 Required UDAP Metadata</a>
    /// </summary>
    public UdapMetadata()
    {

    }

    /// <summary>
    /// A fixed array with one string element
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapVersionsSupported)]
    public string[]? UdapVersionsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of two or more strings identifying the core UDAP profiles supported by the Authorization Server.
    /// The array <b>SHALL</b> include:
    /// "udap_dcr" for UDAP Dynamic Client Registration, and <br/>
    /// "udap_authn" for UDAP JWT-Based Client Authentication. <br/>
    /// If the grant_types_supported parameter includes the string "client_credentials", then the array SHALL also include: <br/>
    /// "udap_authz" for UDAP Client Authorization Grants using JSON Web Tokens to indicate support for Authorization Extension Objects.
    /// If the server supports the user authentication workflow described in
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/user.html#tiered-oauth-for-user-authentication">Section 6</a>,
    /// then the array SHALL also include: <br/>
    /// "udap_to" for UDAP Tiered OAuth for User Authentication.
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapProfilesSupported)]
    public string[]? UdapProfilesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of zero or more recognized key names for Authorization Extension Objects supported by the Authorization Server.
    /// If the Authorization Server supports the B2B Authorization Extension Object defined in
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/user.html#tiered-oauth-for-user-authentication">Section 6</a>,
    /// then the following key name SHALL be included:
    /// ["hl7-b2b"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapAuthorizationExtensionsSupported)]
    public string[]? UdapAuthorizationExtensionsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#f0ad4e;">conditional</span><br/>
    /// An array of zero or more recognized key names for Authorization Extension Objects required by the
    /// Authorization Server in every token request. This metadata parameter SHALL be present if the value
    /// of the udap_authorization_extensions_supported parameter is not an empty array. If the Authorization
    /// Server requires the B2B Authorization Extension Object defined in
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/b2b.html#b2b-authorization-extension-object"> Section 5.2.1.1</a>
    /// in every token request, then the following key name SHALL be included: <br/>
    /// ["hl7-b2b"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapAuthorizationExtensionsRequired)]
    public string[]? UdapAuthorizationExtensionsRequired { get; set; }

    /// <summary>
    ///  <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of zero or more certification URIs supported by the Authorization Server, e.g.: <br/>
    /// ["https://www.example.com/udap/profiles/example-certification"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapCertificationsSupported)]
    public string[]? UdapCertificationsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#f0ad4e;">conditional</span><br/>
    /// An array of zero or more certification URIs required by the Authorization Server.
    /// This metadata parameter SHALL be present if the value of the udap_certifications_supported
    /// parameter is not an empty array. Example: <br/>
    /// ["https://www.example.com/udap/profiles/example-certification"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapCertificationsRequired)]
    public string[]? UdapCertificationsRequired { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of one or more grant types supported by the Authorization Server, e.g.:<br/>
    /// ["authorization_code", "refresh_token",  "client_credentials"]
    /// The "refresh_token" grant type SHALL only be included if the "authorization_code" grant type is also included.
    /// See <see cref="IdentityModel.OidcConstants.GrantTypes"/> for supported grant types
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.GrantTypesSupported)]
    public string[]? GrantTypesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5bc0de;">optional</span><br/>
    /// An array of one or more strings containing scopes supported by the Authorization Server.
    /// The server MAY support different subsets of these scopes for different client types or
    /// entities. Example for a server that also supports SMART App Launch v1 scopes:<br/>
    /// ["openid", "launch/patient", "system/Patient.read", "system/AllergyIntolerance.read", "system/Procedures.read"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.ScopesSupported)]
    public string[]? ScopesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#f0ad4e;">conditional</span><br/>
    /// A string containing the absolute URL of the Authorization Server's authorization endpoint.
    /// This parameter SHALL be present if the value of the grant_types_supported parameter includes
    /// the string "authorization_code"
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.AuthorizationEndpoint)]
    public string? AuthorizationEndpoint { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// A string containing the absolute URL of the Authorization Server's token endpoint for
    /// UDAP JWT-Based Client Authentication.
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.TokenEndpoint)]
    public string? TokenEndpoint { get; set; }


    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// Fixed array with one value: ["private_key_jwt"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.TokenEndpointAuthMethodsSupported)]
    public string[]? TokenEndpointAuthMethodsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// Array of strings identifying one or more signature algorithms supported by the
    /// Authorization Server for validation of signed JWTs submitted to the token endpoint
    /// for client authentication. For example:<br/>
    /// ["RS256", "ES384"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.TokenEndpointAuthSigningAlgValuesSupported)]
    public string[]? TokenEndpointAuthSigningAlgValuesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// Array of strings identifying one or more signature algorithms supported by the
    /// Authorization Server for validation of signed JWTs submitted to the token endpoint
    /// for client authentication. For example:<br/>
    /// ["RS256", "ES384"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.RegistrationEndpoint)]
    public string? RegistrationEndpoint { get; set; }

    /// <summary>
    /// <span style="background-color:#5bc0de;">recommended</span><br/>
    /// Array of strings identifying one or more signature algorithms supported by the
    /// Authorization Server for validation of signed software statements, certification,
    /// and endorsements submitted to the registration endpoint. For example:<br/>
    /// ["RS256", "ES384"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.RegistrationEndpointJwtSigningAlgValuesSupported)]
    public string[]? RegistrationEndpointJwtSigningAlgValuesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// A string containing a JWT listing the server's endpoints, as defined in
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/branches/main/discovery.html#signed-metadata-elements">[Section 2.3].</a>
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.SignedMetadata)]
    public string? SignedMetadata { get; set; }
}