#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Udap.Model;
using Udap.Model.UdapAuthenticationExtensions;
using Udap.Server.Validation;
using Udap.Tefca.Model;

namespace Udap.Tefca.Server;

/// <summary>
/// Validates TEFCA-specific token request rules per the Facilitated FHIR SOP v2.0 Section 6.11:
///
/// 1. Declares required extensions per grant type (hl7-b2b for client_credentials,
///    none for authorization_code).
/// 2. Enforces allowed purpose_of_use codes from the TEFCA Exchange Purposes SOP v5.1.
/// 3. Enforces max 1 purpose_of_use entry per Table 2 ("A length 1 array").
/// 4. The <c>purpose_of_use</c> in the hl7-b2b AEO must match the exchange purpose
///    coded in the client's registered SAN URI.
/// 5. If the registered exchange purpose is <c>T-IAS</c> and the grant type is
///    <c>client_credentials</c>, the <c>tefca_ias</c> AEO must be present.
/// 6. A <c>tefca_ias</c> AEO, when present, must carry an <c>id_token</c> (Table 4).
/// 7. Optionally (see <see cref="TefcaValidationOptions.EnforceTreatmentOrganizationIdentifiers"/>),
///    Treatment token requests must carry the NPI/TIN in <c>organization_name</c> and an
///    <c>organization_id</c> per the Treatment XP Implementation SOP v2.0 Section 6.2.
///
/// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/02/SOP-Facilitated-FHIR-Implementation-2.0-Draft-508.pdf#page=15">
/// SOP v2.0 — Table 2 and IAS Queries</a>
/// </summary>
public class TefcaTokenValidator : ICommunityTokenValidator
{
    private readonly TefcaValidationOptions _options;

    /// <summary>
    /// All TEFCA Exchange Purpose codes in full OID URI format, derived from
    /// <see cref="TefcaConstants.ExchangePurposeCodes.All"/>.
    /// <a href="https://rce.sequoiaproject.org/wp-content/uploads/2026/07/Exchange-Purposes-SOP-v5.1_7.1.2026_508.pdf#page=6">
    /// SOP: Exchange Purposes (XPs) v5.1 — Table 1</a>
    /// </summary>
    internal static readonly HashSet<string> AllTefcaXpCodes = new(
        TefcaConstants.ExchangePurposeCodes.All.Select(code =>
            $"urn:oid:{TefcaConstants.ExchangePurposeCodes.Oid}#{code}"),
        StringComparer.Ordinal);

    public TefcaTokenValidator(IOptions<TefcaValidationOptions> options)
    {
        _options = options.Value;
    }

    /// <inheritdoc />
    public bool AppliesToCommunity(string communityName)
        => _options.Communities.Contains(communityName);

    /// <summary>
    /// Returns TEFCA SOP v2.0 validation rules for the given grant type.
    /// <list type="bullet">
    /// <item><c>client_credentials</c>: hl7-b2b required, max 1 purpose_of_use from TEFCA XP codes</item>
    /// <item><c>authorization_code</c>: no extensions required (per spec), same POU rules if extensions are present</item>
    /// </list>
    /// </summary>
    public CommunityValidationRules? GetValidationRules(string? grantType)
    {
        var requiredExtensions = grantType switch
        {
            "client_credentials" => new HashSet<string> { UdapConstants.UdapAuthorizationExtensions.Hl7B2B },
            "authorization_code" => [],
            _ => null
        };

        return new CommunityValidationRules
        {
            RequiredExtensions = requiredExtensions,
            AllowedPurposeOfUse = AllTefcaXpCodes,
            MaxPurposeOfUseCount = 1
        };
    }

    /// <inheritdoc />
    public Task<AuthorizationExtensionValidationResult> ValidateAsync(
        UdapAuthorizationExtensionValidationContext context)
    {
        if (string.IsNullOrEmpty(context.SanUri))
        {
            return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                "TEFCA client has no registered SAN URI"));
        }

        var hashIndex = context.SanUri.LastIndexOf('#');
        if (hashIndex < 0 || hashIndex == context.SanUri.Length - 1)
        {
            return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                "TEFCA client's registered SAN URI does not contain an exchange purpose"));
        }

        var registeredXp = context.SanUri.Substring(hashIndex + 1);

        // IAS + client_credentials requires tefca_ias AEO (SOP v2.0 Section 6.11, IAS Queries #3)
        if (string.Equals(registeredXp, TefcaConstants.ExchangePurposeCodes.IndividualAccessServices, StringComparison.Ordinal)
            && string.Equals(context.GrantType, "client_credentials", StringComparison.OrdinalIgnoreCase))
        {
            if (context.Extensions == null
                || !context.Extensions.ContainsKey(TefcaConstants.UdapAuthorizationExtensions.TEFCAIAS))
            {
                return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    "TEFCA IAS client_credentials token request requires the 'tefca_ias' authorization extension"));
            }
        }

        if (context.Extensions == null || context.Extensions.Count == 0)
        {
            return Task.FromResult(AuthorizationExtensionValidationResult.Success());
        }

        // id_token is Required in the tefca_ias AEO; respond with invalid_grant if missing
        // (SOP v2.0 Section 6.11, Table 4)
        if (context.Extensions.TryGetValue(TefcaConstants.UdapAuthorizationExtensions.TEFCAIAS, out var iasValue)
            && iasValue is TEFCAIASAuthorizationExtension ias
            && IsMissing(ias.IdToken))
        {
            return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                "invalid_grant",
                "TEFCA 'tefca_ias' authorization extension requires an 'id_token'"));
        }

        // Treatment XP Implementation SOP v2.0 Section 6.2: the hl7-b2b extension must carry
        // the provider's NPI and/or TIN appended to organization_name, and organization_id
        // must reference the RCE Directory Organization entry. Opt-in via
        // TefcaValidationOptions.EnforceTreatmentOrganizationIdentifiers.
        if (_options.EnforceTreatmentOrganizationIdentifiers
            && (string.Equals(registeredXp, TefcaConstants.ExchangePurposeCodes.Treatment, StringComparison.Ordinal)
                || string.Equals(registeredXp, TefcaConstants.ExchangePurposeCodes.TefcaRequiredTreatment, StringComparison.Ordinal))
            && context.Extensions.TryGetValue(UdapConstants.UdapAuthorizationExtensions.Hl7B2B, out var b2bValue)
            && b2bValue is HL7B2BAuthorizationExtension b2b)
        {
            if (string.IsNullOrWhiteSpace(b2b.OrganizationId))
            {
                return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    "TEFCA Treatment token request requires 'organization_id' referencing the RCE Directory Organization entry"));
            }

            if (b2b.OrganizationName == null || !NpiOrTinPattern.IsMatch(b2b.OrganizationName))
            {
                return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                    "invalid_grant",
                    "TEFCA Treatment token request requires the NPI and/or TIN appended to 'organization_name'"));
            }
        }

        foreach (var (key, value) in context.Extensions)
        {
            if (value is IAuthorizationExtensionObject extObj)
            {
                var purposeOfUse = extObj.GetPurposeOfUse();
                if (purposeOfUse == null || purposeOfUse.Count == 0)
                {
                    continue;
                }

                foreach (var code in purposeOfUse)
                {
                    // Extract XP code from full URI format: urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TREAT
                    var pouCode = code;
                    var pouHashIndex = code.LastIndexOf('#');
                    if (pouHashIndex >= 0 && pouHashIndex < code.Length - 1)
                    {
                        pouCode = code.Substring(pouHashIndex + 1);
                    }

                    if (!string.Equals(pouCode, registeredXp, StringComparison.Ordinal))
                    {
                        return Task.FromResult(AuthorizationExtensionValidationResult.Failure(
                            "invalid_grant",
                            $"purpose_of_use '{pouCode}' does not match registered exchange purpose '{registeredXp}'"));
                    }
                }
            }
        }

        return Task.FromResult(AuthorizationExtensionValidationResult.Success());
    }

    /// <summary>
    /// Matches an NPI (10 digits) or TIN (9 digits) appended to organization_name.
    /// </summary>
    private static readonly Regex NpiOrTinPattern = new(@"\d{9,10}", RegexOptions.Compiled);

    private static bool IsMissing(JsonElement? idToken)
    {
        if (idToken is not { } token)
        {
            return true;
        }

        return token.ValueKind switch
        {
            JsonValueKind.Undefined or JsonValueKind.Null => true,
            JsonValueKind.String => string.IsNullOrWhiteSpace(token.GetString()),
            _ => false
        };
    }
}
