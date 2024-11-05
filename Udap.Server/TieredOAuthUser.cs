﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Duende.IdentityServer;
using IdentityModel;
using Udap.Common.Extensions;

namespace Udap.Server;


/// <summary>
/// Model properties of an IdentityServer user
///
/// Modeled after <see cref="Duende.IdentityServer.IdentityServerUser"/> user
/// </summary>
public class TieredOAuthUser
{
    /// <summary>
    /// Subject ID (mandatory)
    /// </summary>
    public string SubjectId { get; }

    /// <summary>
    /// Display name (optional)
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Identity provider (optional)
    /// </summary>
    public string? IdentityProvider { get; set; }

    /// <summary>
    /// Tenant (optional)
    /// </summary>
    public string? Tenant { get; set; }

    /// <summary>
    /// Authentication methods
    /// </summary>
    public ICollection<string> AuthenticationMethods { get; set; } = new HashSet<string>();

    /// <summary>
    /// Authentication time
    /// </summary>
    public DateTime? AuthenticationTime { get; set; }

    /// <summary>
    /// Additional claims
    /// </summary>
    public ICollection<Claim> AdditionalClaims { get; set; } = new HashSet<Claim>(new ClaimComparer());

    /// <summary>
    /// Initializes a user identity
    /// </summary>
    /// <param name="subjectId">The subject ID</param>
    public TieredOAuthUser(string subjectId)
    {
        if (subjectId.IsMissing()) throw new ArgumentException("SubjectId is mandatory", nameof(subjectId));

        SubjectId = subjectId;
    }

    /// <summary>
    /// Creates an IdentityServer claims principal
    /// </summary>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public ClaimsPrincipal CreatePrincipal()
    {
        if (SubjectId.IsMissing()) throw new ArgumentException("SubjectId is mandatory", nameof(SubjectId));
        var claims = new List<Claim> { new Claim(JwtClaimTypes.Subject, SubjectId) };

        if (DisplayName.IsPresent())
        {
            claims.Add(new Claim(JwtClaimTypes.Name, DisplayName!));
        }

        if (IdentityProvider.IsPresent())
        {
            claims.Add(new Claim(JwtClaimTypes.IdentityProvider, IdentityProvider!));
        }

        if (Tenant.IsPresent())
        {
            claims.Add(new Claim(IdentityServerConstants.ClaimTypes.Tenant, Tenant!));
        }

        if (AuthenticationTime.HasValue)
        {
            claims.Add(new Claim(JwtClaimTypes.AuthenticationTime, new DateTimeOffset(AuthenticationTime.Value).ToUnixTimeSeconds().ToString()));
        }

        if (AuthenticationMethods.Count != 0)
        {
            foreach (var amr in AuthenticationMethods)
            {
                claims.Add(new Claim(JwtClaimTypes.AuthenticationMethod, amr));
            }
        }

        claims.AddRange(AdditionalClaims);

        var id = new ClaimsIdentity(claims.Distinct(new ClaimComparer()), Constants.IdentityServerAuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);
        return new ClaimsPrincipal(id);
    }
}