#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Udap.Client.Client;

public record Pkce
{
    /// <summary>
    /// PKCE generated and used in the authorization code flow.
    /// <a href="https://datatracker.ietf.org/doc/html/rfc7636"/>
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/b2b.html#obtaining-an-authorization-code"/> 
    /// <a href="https://build.fhir.org/ig/HL7/fhir-udap-security-ig/consumer.html#obtaining-an-authorization-code"/>
    /// </summary>
    public Pkce()
    {
        CodeVerifier = GenerateCodeVerifier();
        CodeChallenge = GenerateCodeChallenge(CodeVerifier);
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Base64UrlEncoder.Encode(bytes);
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return Base64UrlEncoder.Encode(challengeBytes);
    }


    public string CodeVerifier { get; }
    public string CodeChallenge { get; }
}