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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Udap.Util.Extensions;
public static class JwtExtensions
{
    public static JsonArray? Getx5cArray(this JsonWebToken jwt)
    {
        if (!jwt.TryGetHeaderValue<string>("x5c", out var x5cArray))
        {
            return [];
        }

        return JsonNode.Parse(x5cArray) as JsonArray;
    }

    public static ICollection<X509Certificate2>? GetCertificateList(this JsonWebToken jwt)
    {
        if (!jwt.TryGetHeaderValue<string>("x5c", out var x5cArray))
        {
            return null;
        }

        var x5cJsonArray = JsonNode.Parse(x5cArray) as JsonArray;

        if (x5cJsonArray == null)
        {
            return null;
        }

        var certificates = new List<X509Certificate2>();

        foreach (var jsonNode in x5cJsonArray)
        {
            if (jsonNode == null)
            {
                return null;
            }

#if NET9_0_OR_GREATER
            certificates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(jsonNode.ToString())));
#else
            certificates.Add(new X509Certificate2(Convert.FromBase64String(jsonNode.ToString())));
#endif
        }

        return certificates;
    }

    public static X509Certificate2? GetPublicCertificate(this JsonWebToken jwt)
    {
        var jsonArray = jwt.Getx5cArray();

        if (jsonArray == null || jsonArray.Count == 0)
        {
            return null;
        }

        return jsonArray.GetPublicCertificate();
    }


    public static X509Certificate2? GetPublicCertificate(this JsonArray jsonArray)
    {
        if (jsonArray.Count == 0)
        {
            return null;
        }

        var firstNode = jsonArray.FirstOrDefault();

        if (firstNode == null)
        {
            return null;
        }

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(firstNode.ToString()));
#else
        return new X509Certificate2(Convert.FromBase64String(firstNode.ToString()));
#endif
    }
}
