#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using IdentityModel;
using Microsoft.Extensions.Options;

namespace Udap.Model;

/// <summary>
/// <a href="http://hl7.org/fhir/us/udap-security/discovery.html#required-udap-metadata">2.2 Required UDAP Metadata</a>
/// </summary>
public class UdapMetadata
{
    private readonly List<UdapMetadataConfig>? _udapMetadataConfigs;

    public UdapMetadataConfig? GetUdapMetadataConfig(string? community = null)
    {
        if (community == null)
        {
            return _udapMetadataConfigs?.FirstOrDefault();
        }

        return _udapMetadataConfigs?.SingleOrDefault(c => c.Community == community);
    }


    /// <summary>
    /// <a href="http://hl7.org/fhir/us/udap-security/discovery.html#required-udap-metadata">2.2 Required UDAP Metadata</a>
    /// </summary>
    [JsonConstructor]
    public UdapMetadata(
        // List<UdapMetadataConfig> udapMetadataConfigs,
        ICollection<string> udapVersionsSupported,
        ICollection<string> udapProfilesSupported,
        ICollection<string> udapAuthorizationExtensionsSupported,
        ICollection<string> udapAuthorizationExtensionsRequired,
        ICollection<string> udapCertificationsSupported,
        ICollection<string> udapCertificationsRequired,
        ICollection<string> grantTypesSupported,
        ICollection<string> scopesSupported,
        ICollection<string> tokenEndpointAuthMethodsSupported,
        ICollection<string> tokenEndpointAuthSigningAlgValuesSupported,
        ICollection<string> registrationEndpointJwtSigningAlgValuesSupported)
    {
        _udapMetadataConfigs = null;
        UdapVersionsSupported = udapVersionsSupported;
        UdapProfilesSupported = udapProfilesSupported;
        UdapAuthorizationExtensionsSupported = udapAuthorizationExtensionsSupported;
        UdapAuthorizationExtensionsRequired = udapAuthorizationExtensionsRequired;
        UdapCertificationsSupported = udapCertificationsSupported;
        UdapCertificationsRequired = udapCertificationsRequired;
        GrantTypesSupported = grantTypesSupported;
        ScopesSupported = scopesSupported;
        TokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
        TokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
        RegistrationEndpointJwtSigningAlgValuesSupported = registrationEndpointJwtSigningAlgValuesSupported;
    }

    /// <summary>
    /// <a href="http://hl7.org/fhir/us/udap-security/discovery.html#required-udap-metadata">2.2 Required UDAP Metadata</a>
    /// </summary>
    public UdapMetadata(IOptionsMonitor<UdapConfig> udapConfig, HashSet<string>? scopes) : this(udapConfig.CurrentValue, scopes)
    {
    }

    public UdapMetadata(UdapConfig udapConfig, IEnumerable<string>? scopes)
    {
        _udapMetadataConfigs = udapConfig.UdapMetadataConfigs;
        UdapVersionsSupported = new HashSet<string> { UdapConstants.UdapVersionsSupportedValue };

        UdapProfilesSupported = new HashSet<string>
        {
                UdapConstants.UdapProfilesSupportedValues.UdapDcr,
                UdapConstants.UdapProfilesSupportedValues.UdapAuthn,
                UdapConstants.UdapProfilesSupportedValues.UdapAuthz,
                //TODO: Code doesn't support this yet.  Also all of this needs to be coded up as a configuration feature
                // UdapConstants.UdapProfilesSupportedValues.UdapTo
        };

        UdapAuthorizationExtensionsSupported = new HashSet<string>
        {
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B
                // "acme-ext"
        };

        UdapAuthorizationExtensionsRequired = new HashSet<string>
        {
                UdapConstants.UdapAuthorizationExtensions.Hl7B2B
        };

        UdapCertificationsSupported = new HashSet<string>
        {
                "http://MyUdapCertification", "http://MyUdapCertification2"
        };

        UdapCertificationsRequired = new HashSet<string> { "http://MyUdapCertification" };

        GrantTypesSupported = new HashSet<string>
        {
                OidcConstants.GrantTypes.AuthorizationCode,
                OidcConstants.GrantTypes.RefreshToken,
                OidcConstants.GrantTypes.ClientCredentials
        };

        ScopesSupported = new HashSet<string>
        {
                OidcConstants.StandardScopes.OpenId,
        };

        if (scopes != null)
        {
            foreach (var scope in scopes)
            {
                ScopesSupported.Add(scope);
            }
        }

        TokenEndpointAuthMethodsSupported = new HashSet<string> { UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethodValue };
        //TODO: All of this should be configurable, via config string and builder pattern.
        TokenEndpointAuthSigningAlgValuesSupported = new HashSet<string> { UdapConstants.SupportedAlgorithm.RS256, UdapConstants.SupportedAlgorithm.RS384 };
        RegistrationEndpointJwtSigningAlgValuesSupported = new HashSet<string> { UdapConstants.SupportedAlgorithm.RS256, UdapConstants.SupportedAlgorithm.RS384 };
    }

    /// <summary>
    /// A fixed array with one string element
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapVersionsSupported)]
    public ICollection<string> UdapVersionsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of two or more strings identifying the core UDAP profiles supported by the Authorization Server.
    /// The array <b>SHALL</b> include:
    /// "udap_dcr" for UDAP Dynamic Client Registration, and <br/>
    /// "udap_authn" for UDAP JWT-Based Client Authentication. <br/>
    /// If the grant_types_supported parameter includes the string "client_credentials", then the array SHALL also include: <br/>
    /// "udap_authz" for UDAP Client Authorization Grants using JSON Web Tokens to indicate support for Authorization Extension Objects.
    /// If the server supports the user authentication workflow described in
    /// <a href="http://hl7.org/fhir/us/udap-security/user.html">Section 6</a>,
    /// then the array SHALL also include: <br/>
    /// "udap_to" for UDAP Tiered OAuth for User Authentication.
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapProfilesSupported)]
    public ICollection<string> UdapProfilesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of zero or more recognized key names for Authorization Extension Objects supported by the Authorization Server.
    /// If the Authorization Server supports the B2B Authorization Extension Object defined in
    /// <a href="http://hl7.org/fhir/us/udap-security/user.html">Section 6</a>,
    /// then the following key name SHALL be included:
    /// ["hl7-b2b"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapAuthorizationExtensionsSupported)]
    public ICollection<string> UdapAuthorizationExtensionsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#f0ad4e;">conditional</span><br/>
    /// An array of zero or more recognized key names for Authorization Extension Objects required by the
    /// Authorization Server in every token request. This metadata parameter SHALL be present if the value
    /// of the udap_authorization_extensions_supported parameter is not an empty array. If the Authorization
    /// Server requires the B2B Authorization Extension Object defined in
    /// <a href="http://hl7.org/fhir/us/udap-security/b2b.html#b2b-authorization-extension-object"> Section 5.2.1.1</a>
    /// in every token request, then the following key name SHALL be included: <br/>
    /// ["hl7-b2b"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapAuthorizationExtensionsRequired)]
    public ICollection<string> UdapAuthorizationExtensionsRequired { get; set; }

    /// <summary>
    ///  <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of zero or more certification URIs supported by the Authorization Server, e.g.: <br/>
    /// ["https://www.example.com/udap/profiles/example-certification"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapCertificationsSupported)]
    public ICollection<string> UdapCertificationsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#f0ad4e;">conditional</span><br/>
    /// An array of zero or more certification URIs required by the Authorization Server.
    /// This metadata parameter SHALL be present if the value of the udap_certifications_supported
    /// parameter is not an empty array. Example: <br/>
    /// ["https://www.example.com/udap/profiles/example-certification"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.UdapCertificationsRequired)]
    public ICollection<string> UdapCertificationsRequired { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// An array of one or more grant types supported by the Authorization Server, e.g.:<br/>
    /// ["authorization_code", "refresh_token",  "client_credentials"]
    /// The "refresh_token" grant type SHALL only be included if the "authorization_code" grant type is also included.
    /// See <see cref="IdentityModel.OidcConstants.GrantTypes"/> for supported grant types
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.GrantTypesSupported)]
    public ICollection<string> GrantTypesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5bc0de;">optional</span><br/>
    /// An array of one or more strings containing scopes supported by the Authorization Server.
    /// The server MAY support different subsets of these scopes for different client types or
    /// entities. Example for a server that also supports SMART App Launch v1 scopes:<br/>
    /// ["openid", "launch/patient", "system/Patient.read", "system/AllergyIntolerance.read", "system/Procedures.read"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.ScopesSupported)]
    public ICollection<string> ScopesSupported { get; set; }

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
    public ICollection<string> TokenEndpointAuthMethodsSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// Array of strings identifying one or more signature algorithms supported by the
    /// Authorization Server for validation of signed JWTs submitted to the token endpoint
    /// for client authentication. For example:<br/>
    /// ["RS256", "ES384"]
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.TokenEndpointAuthSigningAlgValuesSupported)]
    public ICollection<string> TokenEndpointAuthSigningAlgValuesSupported { get; set; }

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
    public ICollection<string> RegistrationEndpointJwtSigningAlgValuesSupported { get; set; }

    /// <summary>
    /// <span style="background-color:#5cb85c;">required</span><br/>
    /// A string containing a JWT listing the server's endpoints, as defined in
    /// <a href="http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements">[Section 2.3].</a>
    /// </summary>
    [JsonPropertyName(UdapConstants.Discovery.SignedMetadata)]
    public string? SignedMetadata { get; set; }


    public ICollection<string> Communities()
    {
        if (_udapMetadataConfigs == null)
        {
            return new List<string>();
        }
        return _udapMetadataConfigs.Select(c => c.Community).ToList();
    }

    public string CommunitiesAsHtml(string path)
    {
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<HTML><head><title>Supported UDAP Communities</title></head>");
        sb.AppendLine("<Body>");

        foreach (var community in Communities())
        {
            sb.AppendLine($"<a href=\"{path}/.well-known/udap?community={community}\" target=\"_blank\">{community}</a><br/>");
        }

        sb.AppendLine("</Body>");
        sb.AppendLine("</HTML>");
        return sb.ToString();
    }

    /// <summary>
    /// Serializes this instance to JSON.
    /// </summary>
    /// <returns>This instance as JSON.</returns>
    /// <remarks>Use <see cref="System.IdentityModel.Tokens.Jwt.JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
    public virtual string SerializeToJson()
    {
        return JsonExtensions.SerializeToJson(this);
    }
}