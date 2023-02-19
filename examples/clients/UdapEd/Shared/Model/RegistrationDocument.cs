#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Serialization;
using Udap.Model;

namespace UdapEd.Shared.Model;
public class RegistrationDocument
{
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ClientId)]
    public string? ClientId { get; set; }

    [JsonPropertyName(UdapConstants.RegistrationRequestBody.SoftwareStatement)]
    public string? SoftwareStatement { get; set; }

    /// <summary>
    /// Issuer of the JWT -- unique identifying client URI. This SHALL match the value of a
    /// uniformResourceIdentifier entry in the Subject Alternative Name extension of the client's
    /// certificate included in the x5c JWT header
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Issuer)]
    public string? Issuer { get; set; }

    /// <summary>
    /// Same as iss. In typical use, the client application will not yet have a client_id from
    /// the Authorization Server
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Subject)]
    public string? Subject { get; set; }

    /// <summary>
    /// The Authorization Server's "registration URL" (the same URL to which the registration
    /// request  will be posted)
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Audience)]
    public string? Audience { get; set; }

    /// <summary>
    /// Expiration time integer for this software statement, expressed in seconds since the
    /// "Epoch" (1970-01-01T00:00:00Z UTC). The exp time SHALL be no more than 5 minutes after
    /// the value of the iat claim.
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Expiration)]
    public long Expiration { get; set; }

    /// <summary>
    /// Issued time integer for this software statement, expressed in seconds since the "Epoch"
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.IssuedAt)]
    public long IssuedAt { get; set; }

    /// <summary>
    /// A nonce string value that uniquely identifies this software statement. This value
    /// SHALL NOT be reused by the client app in another software statement or authentication
    /// JWT before the time specified in the exp claim has passed
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.JwtId)]
    public string? JwtId { get; set; }

    /// <summary>
    /// A string containing the human readable name of the client application
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ClientName)]
    public string? ClientName { get; set; }

    /// <summary>
    /// Web page providing information about the client.
    /// See <a aref="https://datatracker.ietf.org/doc/html/rfc7591#section-2"/>
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ClientUri)]
    public Uri? ClientUri { get; set; }


    /// <summary>
    /// List of redirection URI strings for use in redirect-based flows such as the authorization code and implicit flows.
    /// </summary>
    /// <remarks>
    /// Clients using flows with redirection must register their redirection URI values.
    /// </remarks>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.RedirectUris)]
    public ICollection<string> RedirectUris { get; set; } = new List<string>();

    // /// <summary>
    // /// URL string that references a logo for the client.  If present, the
    // /// server SHOULD display this image to the end-user during approval.
    // /// The value of this field MUST point to a valid image file.  The
    // /// value of this field MAY be internationalized, as described in
    // /// <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-2.2">Section 2.2</a>.
    // /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.LogoUri)]
    public Uri? LogoUri { get; set; }

    /// <summary>
    /// A string containing the human readable name of the client application
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Contacts)]
    public ICollection<string> Contacts { get; set; } = new List<string>();

    /// <summary>
    /// List of OAuth 2.0 grant type strings that the client can use at the token endpoint.
    /// </summary>
    /// <remarks>
    /// Example: "authorization_code", "client_credentials", "refresh_token".
    /// </remarks>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.GrantTypes)]
    public ICollection<string> GrantTypes { get; set; } = new HashSet<string>();

    /// <summary>
    /// Array of strings. If grant_types contains "authorization_code", then this element SHALL
    /// have a fixed value of ["code"], and SHALL be omitted otherwise
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.ResponseTypes)]
    public ICollection<string> ResponseTypes { get; set; } = new HashSet<string>();


    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.TokenEndpointAuthMethod)]
    public string? TokenEndpointAuthMethod { get; set; }


    /// <summary>
    /// String containing a space delimited list of scopes requested by the client application
    /// for use in subsequent requests. The Authorization Server MAY consider this list when
    /// deciding the scopes that it will allow the application to subsequently request. Note
    /// for client apps that also support the SMART App Launch framework: apps requesting the
    /// "client_credentials" grant type SHOULD request system scopes; apps requesting the
    /// "authorization_code" grant type SHOULD request user or patient scopes.
    /// </summary>
    [JsonPropertyName(UdapConstants.RegistrationDocumentValues.Scope)]
    public string? Scope { get; set; }

}
