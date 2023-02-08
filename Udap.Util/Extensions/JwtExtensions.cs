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
        var x5cArray = jwt.GetHeaderValue<string>("x5c");

        if (x5cArray == null)
        {
            return new JsonArray();
        }

        return JsonNode.Parse(x5cArray)?.AsArray();
    }

    public static ICollection<X509Certificate2>? GetCertificateList(this JsonWebToken jwt)
    {
        var x5cArray = jwt.GetHeaderValue<string>("x5c");

        if (x5cArray == null)
        {
            return null;
        }

        var certificates = new List<X509Certificate2>();

        foreach (var jsonNode in JsonNode.Parse(x5cArray)?.AsArray())
        {
            certificates.Add(new X509Certificate2(Convert.FromBase64String(jsonNode.ToString())));
        }
        
        return certificates;
    }

    public static X509Certificate2? GetPublicCertificate(this JsonWebToken jwt)
    {
        var jsonArray = jwt.Getx5cArray();

        if (jsonArray == null || !jsonArray.Any())
        {
            return null;
        }

        return jsonArray.GetPublicCertificate();
    }


    public static X509Certificate2? GetPublicCertificate(this JsonArray jsonArray)
    {
        if (!jsonArray.Any())
        {
            return null;
        }

        var firstNode = jsonArray.FirstOrDefault();

        if (firstNode == null)
        {
            return null;
        }

        return new X509Certificate2(Convert.FromBase64String(firstNode.ToString()));
    }
}
