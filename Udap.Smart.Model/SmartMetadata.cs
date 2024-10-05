// ReSharper disable InconsistentNaming
// ReSharper disable CollectionNeverUpdated.Global
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
namespace Udap.Smart.Model;

/// <summary>
/// FHIR SMART App Launch Metadata Class definition based on HL7 FHIR SMART App Launch Specification v 2.1
/// <a href="https://hl7.org/fhir/smart-app-launch/conformance.html#metadata">https://hl7.org/fhir/smart-app-launch/conformance.html#metadata</a>
/// </summary>
public class SmartMetadata
{

    /// <summary>
    /// CONDITIONAL, String conveying this system’s OpenID Connect Issuer URL.
    /// Required if the server’s capabilities include sso-openid-connect; otherwise, omitted
    /// </summary>
    public string issuer { get; set; }

    /// <summary>
    /// CONDITIONAL, String conveying this system’s JSON Web Key Set URL.
    /// Required if the server’s capabilities include sso-openid-connect; otherwise, optional.
    /// </summary>
    public string jwks_uri { get; set; }

    /// <summary>
    /// REQUIRED, URL to the OAuth2 authorization endpoint.
    /// </summary>
    public string authorization_endpoint { get; set; }

    /// <summary>
    /// REQUIRED, Array of grant types supported at the token endpoint.
    /// The options are “authorization_code” (when SMART App Launch is supported) and
    /// “client_credentials” (when SMART Backend Services is supported).
    /// </summary>
    public ICollection<string> grant_types_supported { get; set; }

    /// <summary>
    /// REQUIRED, URL to the OAuth2 token endpoint.
    /// </summary>
    public string token_endpoint { get; set; }

    /// <summary>
    /// OPTIONAL, array of client authentication methods supported by the token endpoint.
    /// The options are “client_secret_post”, “client_secret_basic”, and “private_key_jwt”.
    /// </summary>
    public ICollection<string> token_endpoint_auth_methods_supported { get; set; }

    /// <summary>
    /// OPTIONAL, If available, URL to the OAuth2 dynamic registration endpoint for this FHIR server.
    /// </summary>
    public string registration_endpoint { get; set; }

    /// <summary>
    /// CONDITIONAL, URL to the EHR’s app state endpoint. SHALL be present when the EHR supports the
    /// smart-app-state capability and the endpoint is distinct from the EHR’s primary endpoint.
    /// </summary>
    public string smart_app_state_endpoint { get; set; }

    /// <summary>
    /// RECOMMENDED, array of scopes a client may request.
    /// See <a href="https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html#quick-start">scopes and launch</a> context.
    /// The server SHALL support all scopes listed here;
    /// additional scopes MAY be supported (so clients should not consider this an exhaustive list)
    /// </summary>
    public ICollection<string> scopes_supported { get; set; }

    /// <summary>
    /// RECOMMENDED, Array of OAuth2 response_type values that are supported. Implementers can
    /// refer to response_types defined in OAuth 2.0 (<a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749</a>)
    /// and in <a href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">OIDC</a> Core.
    /// </summary>
    public ICollection<string> response_types_supported { get; set; }

    /// <summary>
    /// RECOMMENDED, URL where an end-user can view which applications currently have
    /// access to data and can make adjustments to these access rights.
    /// </summary>
    public string management_endpoint { get; set; }

    /// <summary>
    /// RECOMMENDED, URL to a server’s introspection endpoint that can be used to validate a token.
    /// </summary>
    public string introspection_endpoint { get; set; }

    /// <summary>
    /// RECOMMENDED, URL to a server’s revoke endpoint that can be used to revoke a token.
    /// </summary>
    public string revocation_endpoint { get; set; }

    /// <summary>
    /// REQUIRED, Array of strings representing SMART capabilities
    /// (e.g., sso-openid-connect or launch-standalone) that the server supports.
    /// </summary>
    public ICollection<string> capabilities { get; set; }

    /// <summary>
    /// REQUIRED, Array of PKCE code challenge methods supported. The S256 method
    /// SHALL be included in this list, and the plain method SHALL NOT be included in this list.
    /// </summary>
    public ICollection<string> code_challenge_methods_supported { get; set; }
}
