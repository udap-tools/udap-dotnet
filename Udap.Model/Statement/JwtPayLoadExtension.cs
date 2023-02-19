#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Udap.Model.Registration;

namespace Udap.Model.Statement;

/// <summary>
/// JwtPayLoad already implements the <see cref="ISoftwareStatementSerializer"/>
/// members.
/// </summary>
public class JwtPayLoadExtension : JwtPayload, ISoftwareStatementSerializer
{
    public JwtPayLoadExtension(IEnumerable<Claim> claims) : base(claims) { }

    public JwtPayLoadExtension(string? issuer, string? audience, IEnumerable<Claim> claims, DateTime? notBefore, DateTime? expires)
        : base(issuer, audience, claims, notBefore, expires, null) { }
}
