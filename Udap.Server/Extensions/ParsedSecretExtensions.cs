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
    /// <summary>
    /// The key that signs a UDAP client assertion: the public key of the first x5c certificate.
    /// UDAP JWT-Based Client Authentication section 6.1 takes the key from cert1 only; that is also
    /// the certificate whose trust chain is validated, so the other x5c entries must never sign.
    /// </summary>
    public static IEnumerable<SecurityKey>? GetUdapKeys(this ParsedSecret secret)
    {
        var jsonWebToken = new JsonWebToken(secret.Credential as string);
        if (!jsonWebToken.TryGetHeaderValue<List<string>>("x5c", out var x5cArray) || x5cArray.Count == 0)
        {
            return null;
        }

#if NET9_0_OR_GREATER
        var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5cArray[0]));
#else
        var certificate = new X509Certificate2(Convert.FromBase64String(x5cArray[0]));
#endif
        if (certificate.PublicKey.GetRSAPublicKey() != null)
        {
            return [new X509SecurityKey(certificate)];
        }

        return [new ECDsaSecurityKey(certificate.PublicKey.GetECDsaPublicKey())];
    }

    public static Udap.Common.Models.ParsedSecret ToModel(this ParsedSecret secret)
    {
        return new Common.Models.ParsedSecret()
            { Credential = secret.Credential, Id = secret.Id, Properties = secret.Properties, Type = secret.Type };
    }
}
