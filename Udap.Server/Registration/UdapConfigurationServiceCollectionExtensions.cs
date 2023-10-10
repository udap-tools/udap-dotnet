#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;
using Udap.Server.Infrastructure.Clock;
using Udap.Server.Registration;
using Udap.Server.Validation;
using Udap.Server.Validation.Default;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

public static class UdapConfigurationServiceCollectionExtensions
{

    /// <summary>
    /// Register a <see cref="UdapDynamicClientRegistrationEndpoint"/> and a
    /// <see cref="UdapDynamicClientRegistrationValidator"/>.
    /// Remember to supply a IUdapClientRegistrationStore to access the certificate anchors
    /// and storage process for new client registrations.
    /// </summary>
    /// <param name="services">IServiceCollection</param>
    /// <returns></returns>
    public static IUdapServiceBuilder AddUdapServerConfiguration(this IUdapServiceBuilder builder)
    {
        builder.Services.TryAddSingleton<IScopeExpander, DefaultScopeExpander>();
        builder.Services.AddScoped<UdapDynamicClientRegistrationEndpoint>();
#if NET8_0_OR_GREATER
        services.TryAddTransient<IClock, DefaultClock>();
#else
        builder.Services.TryAddTransient<IClock, LegacyClock>();
#endif
        builder.Services.TryAddTransient<IUdapDynamicClientRegistrationValidator, UdapDynamicClientRegistrationValidator>();
        builder.Services.TryAddSingleton<TrustChainValidator>();
        
        return builder;
    }


    public static IUdapServiceBuilder AddUdapSigningCredentials(this IUdapServiceBuilder builder)
    {
        builder.Services.AddSingleton<IEnumerable<ISigningCredentialStore>>(resolver =>
        {
            var udapMetadataOptions = resolver.GetRequiredService<IOptionsMonitor<UdapMetadataOptions>>().CurrentValue;
            var signingCredentialStore = new List<ISigningCredentialStore>();
            var certStore = resolver.GetRequiredService<IPrivateCertificateStore>();
            certStore.Resolve();

            foreach (var issued in certStore.IssuedCertificates)
            {
                if (issued.Certificate.GetECDsaPublicKey() != null)
                {
                    AddEcdsaSigningCredentialStore(issued, udapMetadataOptions, signingCredentialStore);
                }
                else
                {
                    AddRsaSigningCredentialStore(issued, udapMetadataOptions, signingCredentialStore);
                }
            }

            return signingCredentialStore.AsEnumerable();
        });

        builder.Services.AddSingleton<IEnumerable<IValidationKeysStore>>(resolver =>
        {
            var udapMetadataOptions = resolver.GetRequiredService<IOptionsMonitor<UdapMetadataOptions>>().CurrentValue;
            var validationKeyStore = new List<IValidationKeysStore>();
            var certStore = resolver.GetRequiredService<IPrivateCertificateStore>();
            certStore.Resolve();

            foreach (var issued in certStore.IssuedCertificates)
            {
                if (issued.Certificate.GetECDsaPublicKey() != null)
                {
                    AddEcdsaValidationKeysStore(issued, udapMetadataOptions, validationKeyStore);
                }
                else
                {
                    AddRsaValidationKeysStore(issued, udapMetadataOptions, validationKeyStore);
                }
            }

            return validationKeyStore.AsEnumerable();
        });

        return builder;
    }

    private static void AddRsaValidationKeysStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<IValidationKeysStore> validationKeyStore)
    {
        var supportedAlgs = udapMetadataOptions.UdapMetadataConfigs
            .Single(c => c.Community == issued.Community).SignedMetadataConfig.TokenSigningAlgorithms;

        if (!supportedAlgs.Any())
        {
            supportedAlgs = DefaultAlgorithms.RsaTokenSigningAlgorithms;
        }

        foreach (var supportedAlg in supportedAlgs)
        {
            var key = new X509SecurityKey(issued.Certificate);
            key.KeyId += supportedAlg;
            var credential = new SigningCredentials(key, supportedAlg);

            var keyInfo = new SecurityKeyInfo
            {
                Key = credential.Key,
                SigningAlgorithm = supportedAlg
            };

            validationKeyStore.Add(new InMemoryValidationKeysStore(new[] { keyInfo }));
        }
    }


    private static void AddEcdsaValidationKeysStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<IValidationKeysStore> validationKeyStore)
    {
        var supportedAlgs = udapMetadataOptions.UdapMetadataConfigs
            .Single(c => c.Community == issued.Community).SignedMetadataConfig.TokenSigningAlgorithms;

        if (!supportedAlgs.Any())
        {
            supportedAlgs = DefaultAlgorithms.EcdsaTokenSigningAlgorithms;
        }

        var key = issued.Certificate.GetECDsaPrivateKey();
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            //
            // Windows work around.  Otherwise works on Linux
            // Short answer: Windows behaves in such a way when importing the pfx
            // it creates the CNG key so it can only be exported encrypted
            // https://github.com/dotnet/runtime/issues/77590#issuecomment-1325896560
            // https://stackoverflow.com/a/57330499/6115838
            //
            var encryptedPrivKeyBytes = key?.ExportEncryptedPkcs8PrivateKey(
                "ILikePasswords",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            ecdsa.ImportEncryptedPkcs8PrivateKey("ILikePasswords".AsSpan(), encryptedPrivKeyBytes.AsSpan(),
                out int _);
        }
        else
        {
            ecdsa.ImportECPrivateKey(key?.ExportECPrivateKey(), out _);
        }

        foreach (var supportedAlg in supportedAlgs)
        {
            var ecDsaSecurityKey = new ECDsaSecurityKey(ecdsa);
            ecDsaSecurityKey.KeyId += issued.Thumbprint + supportedAlg;
            var credential = new SigningCredentials(ecDsaSecurityKey, supportedAlg)
            {
                // If this routine is called multiple times then you must supply the CryptoProvider factory without caching.
                // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1302#issuecomment-606776893
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            var keyInfo = new SecurityKeyInfo
            {
                Key = credential.Key,
                SigningAlgorithm = supportedAlg
            };

            validationKeyStore.Add(new InMemoryValidationKeysStore(new[] { keyInfo }));
        }
    }
    private static void AddRsaSigningCredentialStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<ISigningCredentialStore> signingCredentialStore)
    {
        var supportedAlgs = udapMetadataOptions.UdapMetadataConfigs
            .Single(c => c.Community == issued.Community).SignedMetadataConfig.TokenSigningAlgorithms;

        if (!supportedAlgs.Any())
        {
            supportedAlgs = DefaultAlgorithms.RsaTokenSigningAlgorithms;
        }

        foreach (var supportedAlg in supportedAlgs)
        {
            var key = new X509SecurityKey(issued.Certificate);
            key.KeyId += supportedAlg;
            var credential = new SigningCredentials(key, supportedAlg);
            signingCredentialStore.Add(new InMemorySigningCredentialsStore(credential));
        }
    }

    private static void AddEcdsaSigningCredentialStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<ISigningCredentialStore> signingCredentialStore)
    {
        var supportedAlgs = udapMetadataOptions.UdapMetadataConfigs
            .Single(c => c.Community == issued.Community).SignedMetadataConfig.TokenSigningAlgorithms;

        if (!supportedAlgs.Any())
        {
            supportedAlgs = DefaultAlgorithms.EcdsaTokenSigningAlgorithms;
        }

        var key = issued.Certificate.GetECDsaPrivateKey();
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            //
            // Windows work around.  Otherwise works on Linux
            // Short answer: Windows behaves in such a way when importing the pfx
            // it creates the CNG key so it can only be exported encrypted
            // https://github.com/dotnet/runtime/issues/77590#issuecomment-1325896560
            // https://stackoverflow.com/a/57330499/6115838
            //
            var encryptedPrivKeyBytes = key?.ExportEncryptedPkcs8PrivateKey(
                "ILikePasswords",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            ecdsa.ImportEncryptedPkcs8PrivateKey("ILikePasswords".AsSpan(), encryptedPrivKeyBytes.AsSpan(),
                out int _);
        }
        else
        {
            ecdsa.ImportECPrivateKey(key?.ExportECPrivateKey(), out _);
        }

        

        foreach (var supportedAlg in supportedAlgs)
        {
            var ecDsaSecurityKey = new ECDsaSecurityKey(ecdsa);
            ecDsaSecurityKey.KeyId += issued.Thumbprint + supportedAlg;
            var credential = new SigningCredentials(ecDsaSecurityKey, supportedAlg)
            {
                // If this routine is called multiple times then you must supply the CryptoProvider factory without caching.
                // See: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/1302#issuecomment-606776893
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            
            signingCredentialStore.Add(new InMemorySigningCredentialsStore(credential));
        }
    }
}