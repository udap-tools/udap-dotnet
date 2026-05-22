#region (c) 2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;

namespace Udap.Server.Extensions;

public static class ParsedSecretExtensions
{
    public static IEnumerable<SecurityKey>? GetUdapKeys(this ParsedSecret secret)
    {
        var jsonWebToken = new JsonWebToken(secret.Credential as string);
        if (!jsonWebToken.TryGetHeaderValue<List<string>>("x5c", out var x5cArray))
        {
            return null;
        }

        var certificates = x5cArray
#if NET9_0_OR_GREATER
            .Select(s => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(s.ToString())))
#else
            .Select(s => new X509Certificate2(Convert.FromBase64String(s.ToString())))
#endif
            .Select(c =>
            {
                if (c.PublicKey.GetRSAPublicKey() != null)
                {
                    return (SecurityKey)new X509SecurityKey(c);
                }

                return (SecurityKey)new ECDsaSecurityKey(c.PublicKey.GetECDsaPublicKey());
            })
            .ToList();

        return certificates;
    }

    public static Udap.Common.Models.ParsedSecret ToModel(this ParsedSecret secret)
    {
        return new Common.Models.ParsedSecret()
            { Credential = secret.Credential, Id = secret.Id, Properties = secret.Properties, Type = secret.Type };
    }
}
