#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Model.Registration;

/// <summary>
/// See <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2">rfc7591 section 3.2.2</a>
/// </summary>
public static class UdapDynamicClientRegistrationErrors
{
    public const string InvalidClientMetadata = "invalid_client_metadata";
    public const string InvalidSoftwareStatement = "invalid_software_statement";
    public const string UnapprovedSoftwareStatement = "unapproved_software_statement";
}

public static class UdapDynamicClientRegistrationErrorDescriptions
{
    public const string SubIsMissing = "software_statement sub is missing";
    public const string SubNotEqualToIss = "software_statement sub is not equal to iss";
    public const string UntrustedCertificate = "Untrusted: Certificate is not a member of community";
    public const string InvalidAud = "software_statement aud is invalid";
    public const string InvalidMatchAud = "software_statement aud does not match registration endpoint";
    public const string ExpMissing = "software_statement exp is missing";
    public const string ExpExpired = "software_statement exp is expired";
    public const string CannotFindorParseX5c = "software_statement x5c cannot find or parse";
    public const string IssuedAtMissing = "software_statement iat is missing";
    public const string IssuedAtInFuture = "software_statement iat is in the future";
    public const string FailedTokenValidation = "Failed JsonWebTokenHandler.ValidateToken";
    public const string InvalidJti = "software_statement jti is invalid";
    public const string Replay = "software_statement replayed";

    public const string ClientNameMissing = "client_name is missing";
    public const string LogoMissing = "logo_uri is missing";
    public const string LogoInvalidUri = "logo_uri is not a valid uri";
    public const string LogoInvalidContentType = "logo_uri is not a valid content-type";
    public const string LogoInvalidScheme = "logo_uri is not a valid https schema";
    public const string LogoCannotBeResolved = "logo_uri cannot be resolved";
    public const string GrantTypeMissing = "grant_types is missing";
    public const string ResponseTypesMissing = "invalid_client_metadata response_types is missing";

    public const string TokenEndpointAuthMethodMissing = "invalid_client_metadata token_endpoint_auth_method is missing";

    public const string MissingValidationResult = "Missing validation result.";
    public const string MalformedMetaDataDocument = "Malformed metadata document";

    public const string ClientCredentialsRefreshError = "Client credentials does not support refresh tokens";
    public const string UnsupportedGrantType = "Unsupported grant type";
    public const string MalformedRedirectUri = "Malformed redirect uri";
    public const string RedirectUriRequiredForAuthCode = "Redirect uri is required for authorization_code grant type";
    
}