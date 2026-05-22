#region (c) 2022-2025 Joseph Shook. All rights reserved.
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

namespace Udap.Server.Storage.Extensions;

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
            .Any(s => s.Type == UdapServerConstants.SecretTypes.UDAP_SAN_URI_ISS_NAME))
        {
            var communityId = enumerable.SingleOrDefault(s =>
                    s.Type == UdapServerConstants.SecretTypes.UDAP_COMMUNITY)
                ?.Value;

            if (communityId != null)
            {
                var id = long.Parse(communityId);

                return await store.GetCommunityCertificates(id);
            }
        }

        return null;
    }
    
    public static X509Certificate2? GetUdapEndCert(this Udap.Common.Models.ParsedSecret secret)
    {
        var jsonWebToken = new JsonWebToken(secret.Credential as string);
        
        if(!jsonWebToken.TryGetHeaderValue<List<string>>("x5c", out var x5cArray))
        {
            return null;
        }

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5cArray.First()));
#else
        return new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
#endif
    }
}