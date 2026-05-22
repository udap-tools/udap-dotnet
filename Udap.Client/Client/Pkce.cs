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

namespace Udap.Client;

/// <summary>
/// Represents a Proof Key for Code Exchange (PKCE) pair as defined in RFC 7636, used in the UDAP authorization code flow.
/// </summary>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc7636"/>
public record Pkce
{
    /// <summary>
    /// Initializes a new <see cref="Pkce"/> instance, generating a cryptographically random code verifier and its S256 challenge.
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
        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        return Base64UrlEncoder.Encode(challengeBytes);
    }


    /// <summary>
    /// Gets the high-entropy cryptographic random string used as the PKCE code verifier.
    /// </summary>
    public string CodeVerifier { get; }

    /// <summary>
    /// Gets the Base64url-encoded SHA-256 hash of the <see cref="CodeVerifier"/>, sent as the code challenge in the authorization request.
    /// </summary>
    public string CodeChallenge { get; }
}