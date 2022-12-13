#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Duende.IdentityServer.Models;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Server.Extensions;

public static class ClientExtensions
{
    /// <summary>
    /// Constructs a certificate chain from a Secret collection
    /// 
    /// </summary>
    /// <param name="secrets">The secrets</param>
    /// <returns>List{X509Certificate2Collection}</returns>
    public static Task<List<X509Certificate2Collection>> GetUdapChainsAsync(this IEnumerable<Secret> secrets)
    {
        var secretList = secrets.ToList().AsReadOnly();
        var certificates = GetCertificates(secretList).ToList();

        return Task.FromResult(certificates);
    }

    private static IEnumerable<X509Certificate2Collection> GetCertificates(IEnumerable<Secret> secrets)
    {
        var joe = secrets
            .Where(s => s.Type == UdapServerConstants.SecretTypes.Udapx5c)
            .Select(s =>
            {
                var x5CArray = JsonNode.Parse(s.Value)?.AsArray();

                if (x5CArray == null)
                {
                    return null;
                }

                var certChain = new X509Certificate2Collection();
                foreach (var item in x5CArray)
                {
                    certChain.Add(new X509Certificate2(Convert.FromBase64String(item.ToString())));
                }

                return certChain;
            })
            .Where(c => c != null)
            .ToList();

        return joe;
    }

    public static Task<List<SecurityKey>> GetUdapKeysAsync(this ParsedSecret secret)
    {
        var jsonWebToken = new JsonWebToken(secret.Credential as string);
        var x5cArray = jsonWebToken.GetHeaderValue<List<string>>("x5c");

        var certificates = x5cArray
            .Select(s => new X509Certificate2(Convert.FromBase64String(s.ToString())))
            .Select(c => (SecurityKey)new X509SecurityKey(c))
            .ToList();
        
        return Task.FromResult(certificates);
    }

    public static X509Certificate2 GetUdapEndCertAsync(this ParsedSecret secret)
    {
        var jsonWebToken = new JsonWebToken(secret.Credential as string);
        var x5cArray = jsonWebToken.GetHeaderValue<List<string>>("x5c");

        return new X509Certificate2(Convert.FromBase64String(x5cArray.First()));
    }
}