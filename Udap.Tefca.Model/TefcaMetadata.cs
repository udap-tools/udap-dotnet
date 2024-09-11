#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Udap.Model;

namespace Udap.Tefca.Model;

public class TefcaMetadata : UdapMetadata
{

    /// <summary>
    /// <a href="http://hl7.org/fhir/us/udap-security/discovery.html#required-udap-metadata">2.2 Required UDAP Metadata</a>
    /// </summary>
    [JsonConstructor]
    public TefcaMetadata(
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
        ICollection<string> registrationEndpointJwtSigningAlgValuesSupported,
        ICollection<string> certificationUris) : base(udapVersionsSupported, udapProfilesSupported, udapAuthorizationExtensionsSupported, udapAuthorizationExtensionsRequired, udapCertificationsSupported, udapCertificationsRequired, grantTypesSupported, scopesSupported, tokenEndpointAuthMethodsSupported, tokenEndpointAuthSigningAlgValuesSupported, registrationEndpointJwtSigningAlgValuesSupported)
    {
        UdapMetadataConfigs = null;
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
        CertificationUris = certificationUris;
    }

    private TefcaMetadata(
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
        ICollection<string> registrationEndpointJwtSigningAlgValuesSupported,
        ICollection<string> certificationUris,
        List<UdapMetadataConfig>? udapMetadataConfigs = null) : base(udapVersionsSupported, udapProfilesSupported, udapAuthorizationExtensionsSupported, udapAuthorizationExtensionsRequired, udapCertificationsSupported, udapCertificationsRequired, grantTypesSupported, scopesSupported, tokenEndpointAuthMethodsSupported, tokenEndpointAuthSigningAlgValuesSupported, registrationEndpointJwtSigningAlgValuesSupported)
    {
        UdapMetadataConfigs = udapMetadataConfigs;
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
        CertificationUris = certificationUris;
    }
    
    public TefcaMetadata(TefcaMetadataOptions udapMetadataOptions) : this(udapMetadataOptions, null)
    {
        
    }

    /// <summary>
    /// <a href="http://hl7.org/fhir/us/udap-security/discovery.html#required-udap-metadata">2.2 Required UDAP Metadata</a>
    /// </summary>
    public TefcaMetadata(IOptionsMonitor<TefcaMetadataOptions> udapMetadataOptions, HashSet<string>? scopes) : base(udapMetadataOptions.CurrentValue, scopes)
    {
    }

    public TefcaMetadata(TefcaMetadataOptions udapMetadataOptions, IEnumerable<string>? scopes = null) : base(udapMetadataOptions, scopes)
    {
        CertificationName = udapMetadataOptions.CertificationName;

        if (udapMetadataOptions.CertificationUris.Any())
        {
            CertificationUris = udapMetadataOptions.CertificationUris;
        }
    }

    /// <summary>
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2024/07/SOP-Facilitated-FHIR-Implementation_508-1.pdf#page=15">TEFCA SOP - Facilitated FHIR Implementation Guide</a>
    /// </summary>
    [JsonPropertyName(TefcaConstants.Discovery.CertificationUris)]
    public ICollection<string>? CertificationUris { get; set; }

    /// <summary>
    /// /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2024/07/SOP-Facilitated-FHIR-Implementation_508-1.pdf#page=15">TEFCA SOP - Facilitated FHIR Implementation Guide</a>
    /// </summary>
    [JsonPropertyName(TefcaConstants.Discovery.CertificationName)]
    public string? CertificationName { get; set; }
}
