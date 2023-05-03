#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Math.EC;
using Udap.Model.Registration;
using ECCurve = System.Security.Cryptography.ECCurve;

namespace Udap.Model.Statement;
public class SignedSoftwareStatementBuilder<T> where T: class, ISoftwareStatementSerializer
{
    private readonly X509Certificate2 _certificate;
    private readonly T _document;

    private SignedSoftwareStatementBuilder(X509Certificate2 certificate, T document)
    {
        _certificate = certificate;
        _document = document;
    }

    public static SignedSoftwareStatementBuilder<T> Create(X509Certificate2 certificate, T document)
    {
        return new SignedSoftwareStatementBuilder<T>(certificate, document);
    }
     
    //
    // No With items...
    // There are plenty of interesting scenarios like loading the x5c hierarchy where
    // we could add more builder methods
    //

    public string Build(string? algorithm = UdapConstants.SupportedAlgorithm.RS256)
    {
        algorithm ??= UdapConstants.SupportedAlgorithm.RS256;

#if NET5_0_OR_GREATER
        //
        // Short circuit to ECDSA
        //
        if (_certificate.GetECDsaPublicKey() != null)
        {
            return BuildECDSA();
        }
#endif
        var securityKey = new X509SecurityKey(_certificate);
        var signingCredentials = new SigningCredentials(securityKey, algorithm);

        var pem = Convert.ToBase64String(_certificate.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = _document.Base64UrlEncode();
        var encodedSignature =
            JwtTokenUtilities.CreateEncodedSignature(string.Concat(encodedHeader, ".", encodedPayload),
                signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        return signedSoftwareStatement;
    }

#if NET5_0_OR_GREATER

    public string BuildECDSA(string? algorithm = UdapConstants.SupportedAlgorithm.ES384)
    {

        algorithm ??= UdapConstants.SupportedAlgorithm.ES384;

        var key = _certificate.GetECDsaPrivateKey();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

#if Windows
        //
        // Windows work around.  Otherwise works on Linux
        // Short answer: Windows behaves in such a way when importing the pfx
        // it creates the CNG key so it can only be exported encrypted
        // https://github.com/dotnet/runtime/issues/77590#issuecomment-1325896560
        // https://stackoverflow.com/a/57330499/6115838
        //
        byte[] encryptedPrivKeyBytes = key.ExportEncryptedPkcs8PrivateKey(
            "ILikePasswords",
            new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: 100_000));

        ecdsa.ImportEncryptedPkcs8PrivateKey("ILikePasswords".AsSpan(), encryptedPrivKeyBytes.AsSpan(), out int bytesRead);
#else
        ecdsa.ImportECPrivateKey(key?.ExportECPrivateKey(), out _);
#endif

        var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), algorithm)
        {
            // If this routine is called multiple times then you must supply the CryptoProvider factory without caching.
            // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1302#issuecomment-606776893
            CryptoProviderFactory = new CryptoProviderFactory{ CacheSignatureProviders = false}
        };
      
        var pem = Convert.ToBase64String(_certificate.Export(X509ContentType.Cert));
        var jwtHeader = new JwtHeader
        {
            { "alg", signingCredentials.Algorithm },
            { "x5c", new[] { pem } }
        };

        var encodedHeader = jwtHeader.Base64UrlEncode();
        var encodedPayload = _document.Base64UrlEncode();
        var input = string.Concat(encodedHeader, ".", encodedPayload);
        var encodedSignature = JwtTokenUtilities.CreateEncodedSignature(input, signingCredentials);
        var signedSoftwareStatement = string.Concat(encodedHeader, ".", encodedPayload, ".", encodedSignature);

        return signedSoftwareStatement;
}

#endif
}