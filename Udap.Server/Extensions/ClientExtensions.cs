#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Udap.Server.Storage.Stores;

namespace Udap.Server.Extensions;

public static class ClientExtensions
{
    /// <summary>
    /// Constructs a certificate chain from a Secret collection
    /// 
    /// </summary>
    /// <param name="secrets">The secrets</param>
    /// <param name="store"></param>
    /// <returns>List{X509Certificate2Collection}</returns>
    public static async Task<IList<X509Certificate2>?> GetUdapChainsAsync(
        this IEnumerable<Secret> secrets, 
        IUdapClientRegistrationStore store)
    {
        var secretList = secrets.ToList().AsReadOnly();
        var certificates = await GetCertificates(secretList, store);

        if (certificates != null)
        {
            return certificates.ToList();
        }

        return null;
    }

    private static async Task<IEnumerable<X509Certificate2>?> GetCertificates(IEnumerable<Secret> secrets, IUdapClientRegistrationStore store)
    {
        var enumerable = secrets as Secret[] ?? secrets.ToArray();

        if (enumerable
            .Any(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME &&
                      s.Expiration > DateTime.Now.ToUniversalTime()))
        {
            var communityId = enumerable.SingleOrDefault(s =>
                    s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
                ?.Value;

            if (communityId != null)
            {
                var id = long.Parse(communityId);

                var certificates = await store.GetCommunityCertificates(id);
                return certificates;
            }
        }

        return null;
    }

    public static IEnumerable<SecurityKey>? GetUdapKeys(this ParsedSecret secret)
    {
        var jsonWebToken = new JsonWebToken(secret.Credential as string);
        if (!jsonWebToken.TryGetHeaderValue<List<string>>("x5c", out var x5cArray))
        {
            return null;
        }

        var certificates = x5cArray
            .Select(s => new X509Certificate2(Convert.FromBase64String(s.ToString())))
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

    public static X509Certificate2? GetUdapEndCertAsync(this ParsedSecret secret)
    {
        var jsonWebToken = new JsonWebToken(secret.Credential as string);
        
        if(!jsonWebToken.TryGetHeaderValue<List<string>>("x5c", out var x5cArray))
        {
            return null;
        }

        return new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
    }
}