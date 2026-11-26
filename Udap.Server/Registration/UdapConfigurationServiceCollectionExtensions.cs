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
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Udap.Common.Certificates;
using Udap.Common.Models;
using ZiggyCreatures.Caching.Fusion;
using Udap.Model;
using Udap.Server.Configuration;
using Udap.Server.Hosting;
using Udap.Server.Registration;
using Udap.Server.Validation;
using Udap.Server.Validation.Default;

//
// See reason for Microsoft.Extensions.DependencyInjection namespace
// here: https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-usage
//
// ReSharper disable once CheckNamespace
#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static class UdapConfigurationServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="OutboundConnectionOptions"/>, bound from the
    /// <see cref="OutboundConnectionOptions.SectionName"/> configuration section. Safe to call more than once.
    /// </summary>
    public static IServiceCollection AddUdapOutboundConnectionOptions(this IServiceCollection services)
    {
        services.AddOptions<OutboundConnectionOptions>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<OutboundConnectionOptions>, OutboundConnectionOptionsSetup>());
        return services;
    }

    // Binds the section when the host has an IConfiguration; hosts without one keep the defaults.
    private sealed class OutboundConnectionOptionsSetup(IServiceProvider serviceProvider) : IConfigureOptions<OutboundConnectionOptions>
    {
        public void Configure(OutboundConnectionOptions options)
        {
            serviceProvider.GetService<IConfiguration>()?.GetSection(OutboundConnectionOptions.SectionName).Bind(options);
        }
    }

    /// <summary>
    /// Register a <see cref="UdapDynamicClientRegistrationEndpoint"/> and a
    /// <see cref="UdapDynamicClientRegistrationValidator"/>.
    /// Remember to supply a IUdapClientRegistrationStore to access the certificate anchors
    /// and storage process for new client registrations.
    /// </summary>
    /// <param name="builder">IUdapServiceBuilder</param>
    /// <returns></returns>
    public static IUdapServiceBuilder AddUdapServerConfiguration(this IUdapServiceBuilder builder)
    {
        builder.Services.TryAddSingleton<IScopeExpander, DefaultScopeExpander>();
        builder.Services.AddScoped<UdapDynamicClientRegistrationEndpoint>();
        // logo_uri comes from the registering client, so the logo fetch goes through a client that refuses
        // non-public addresses (OutboundConnectionOptions).
        builder.Services.AddUdapOutboundConnectionOptions();
        builder.Services.AddHttpClient(UdapDynamicClientRegistrationValidator.LogoHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp => OutboundConnectGuard.CreateHandler(
                sp.GetRequiredService<IOptions<OutboundConnectionOptions>>().Value,
                sp.GetService<IHostEnvironment>()));
        builder.Services.TryAddTransient<IUdapDynamicClientRegistrationValidator>(sp =>
            ActivatorUtilities.CreateInstance<UdapDynamicClientRegistrationValidator>(
                sp,
                sp.GetRequiredService<IHttpClientFactory>().CreateClient(UdapDynamicClientRegistrationValidator.LogoHttpClientName)));
        builder.Services.TryAddTransient<IUdapDynamicClientRegistrationProcessor, UdapDynamicClientRegistrationProcessor>();
        // Optional chain policy (for example a per-community maximum chain length). Nothing is enforced until
        // the application configures TrustChainValidatorOptions.
        builder.Services.AddOptions<TrustChainValidatorOptions>();
        builder.Services.TryAddSingleton<TrustChainValidator>();

        if (!builder.Services.Any(sd => sd.ServiceType == typeof(UdapCertificateCacheMarker)))
        {
            builder.Services.AddFusionCache(CertificateDownloadCache.CacheName)
                .WithMemoryCache(_ => new MemoryCache(new MemoryCacheOptions
                {
                    SizeLimit = CertificateDownloadCache.DefaultMemoryCacheSizeLimit
                }))
                // A size limit requires every entry to carry a size; downloads set their own.
                .WithDefaultEntryOptions(options => options.Size = 1);
            builder.Services.AddSingleton<UdapCertificateCacheMarker>();
        }

        // AIA and CRL URLs come from certificates, which a registering client presents before they are trusted, so a
        // download must not be redirected somewhere else and must not reach non-public addresses
        // (OutboundConnectionOptions). The handler recycles connections, so DNS changes get through.
        builder.Services.AddHttpClient(CertificateDownloadCache.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp => OutboundConnectGuard.CreateHandler(
                sp.GetRequiredService<IOptions<OutboundConnectionOptions>>().Value,
                sp.GetService<IHostEnvironment>(),
                allowAutoRedirect: false));

        // Built from the named client explicitly: a type-activated singleton would be handed the
        // default HttpClient instead, which follows redirects.
        builder.Services.TryAddSingleton<ICertificateDownloadCache>(sp => new CertificateDownloadCache(
            sp.GetRequiredService<IFusionCacheProvider>(),
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(CertificateDownloadCache.HttpClientName),
            sp.GetRequiredService<ILogger<CertificateDownloadCache>>()));

        return builder;
    }


    /// <summary>
    /// Adds the issued certificates of the <see cref="IPrivateCertificateStore"/> as IdentityServer signing credentials and
    /// validation keys (token signing and the JWKS endpoint), with the algorithms each community's
    /// <c>UdapMetadataOptions:UdapMetadataConfigs</c> entry names. <typeparamref name="TUdapMetadataOptions"/> is bound from
    /// the <c>UdapMetadataOptions</c> configuration section. Every issued certificate's community needs an entry there.
    /// <para>
    /// Opt in only when the UDAP PKI certificates should also be IdentityServer's token signing keys and appear on its JWKS
    /// endpoint. Most servers keep the two apart: IdentityServer's own keys for tokens and the JWKS, the UDAP certificates for
    /// UDAP artifacts such as signed metadata, which use the certificate store directly.
    /// </para>
    /// </summary>
    public static IUdapServiceBuilder AddUdapSigningCredentials<TUdapMetadataOptions>(this IUdapServiceBuilder builder)
        where TUdapMetadataOptions : UdapMetadataOptions
    {
        // The section the credentials' algorithms come from. Binding it here keeps this method self-contained: the metadata
        // document is read from its own file (UdapMetadataOptionsFile), so nothing else binds these options.
        builder.Services.AddOptions<TUdapMetadataOptions>().BindConfiguration(Udap.Common.Constants.UdapMetadataOptionsSectionName);

        builder.Services.AddSingleton<IEnumerable<ISigningCredentialStore>>(resolver =>
        {
            var udapMetadataOptions = resolver.GetRequiredService<IOptionsMonitor<TUdapMetadataOptions>>().CurrentValue;
            var signingCredentialStore = new List<ISigningCredentialStore>();
            var certStore = resolver.GetRequiredService<IPrivateCertificateStore>();
            var timeout = TimeSpan.FromSeconds(udapMetadataOptions.CertificateResolveTimeoutSeconds);

            ResolveCertificates(certStore, timeout);

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
            var udapMetadataOptions = resolver.GetRequiredService<IOptionsMonitor<TUdapMetadataOptions>>().CurrentValue;
            var validationKeyStore = new List<IValidationKeysStore>();
            var certStore = resolver.GetRequiredService<IPrivateCertificateStore>();
            var timeout = TimeSpan.FromSeconds(udapMetadataOptions.CertificateResolveTimeoutSeconds);

            ResolveCertificates(certStore, timeout);

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

    /// <summary>
    /// Waits for the certificate store to load. <see cref="IPrivateCertificateStore.Resolve"/> is asynchronous; reading
    /// <see cref="IPrivateCertificateStore.IssuedCertificates"/> before it completes sees an empty or partial set, which made
    /// the registered credentials depend on whether something else had loaded the store first.
    /// </summary>
    private static void ResolveCertificates(IPrivateCertificateStore certStore, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            certStore.Resolve(cts.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            throw new InvalidOperationException($"Certificate store resolution timed out after {timeout.TotalSeconds} seconds.");
        }
    }

    /// <summary>The metadata configuration for an issued certificate's community, or a clear error naming what is missing.</summary>
    internal static UdapMetadataConfig ConfigFor(UdapMetadataOptions udapMetadataOptions, IssuedCertificate issued) =>
        udapMetadataOptions.UdapMetadataConfigs.FirstOrDefault(c => c.Community == issued.Community)
        ?? throw new InvalidOperationException(
            $"The issued certificate {issued.Certificate.Thumbprint} is for community '{issued.Community}', which has no " +
            $"{Udap.Common.Constants.UdapMetadataOptionsSectionName}:UdapMetadataConfigs entry. Add one, or do not register " +
            "UDAP signing credentials.");

    private static void AddRsaValidationKeysStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<IValidationKeysStore> validationKeyStore)
    {
        var supportedAlgs = ConfigFor(udapMetadataOptions, issued).SignedMetadataConfig.TokenSigningAlgorithms;

        if (supportedAlgs != null && supportedAlgs.Count == 0)
        {
            supportedAlgs = DefaultAlgorithms.RsaTokenSigningAlgorithms;
        }

        if (supportedAlgs != null)
        {
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

                validationKeyStore.Add(new InMemoryValidationKeysStore([keyInfo]));
            }
        }
    }


    private static void AddEcdsaValidationKeysStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<IValidationKeysStore> validationKeyStore)
    {
        var supportedAlgs = ConfigFor(udapMetadataOptions, issued).SignedMetadataConfig.TokenSigningAlgorithms;

        if (supportedAlgs != null && supportedAlgs.Count == 0)
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

        if (supportedAlgs != null)
        {
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

                validationKeyStore.Add(new InMemoryValidationKeysStore([keyInfo]));
            }
        }
    }
    private static void AddRsaSigningCredentialStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<ISigningCredentialStore> signingCredentialStore)
    {
        var supportedAlgs = ConfigFor(udapMetadataOptions, issued).SignedMetadataConfig.TokenSigningAlgorithms;

        if (supportedAlgs != null && supportedAlgs.Count == 0)
        {
            supportedAlgs = DefaultAlgorithms.RsaTokenSigningAlgorithms;
        }

        if (supportedAlgs != null)
        {
            foreach (var supportedAlg in supportedAlgs)
            {
                var key = new X509SecurityKey(issued.Certificate);
                key.KeyId += supportedAlg;
                var credential = new SigningCredentials(key, supportedAlg);
                signingCredentialStore.Add(new InMemorySigningCredentialsStore(credential));
            }
        }
    }

    private static void AddEcdsaSigningCredentialStore(IssuedCertificate issued, UdapMetadataOptions udapMetadataOptions,
        List<ISigningCredentialStore> signingCredentialStore)
    {
        var supportedAlgs = ConfigFor(udapMetadataOptions, issued).SignedMetadataConfig.TokenSigningAlgorithms;

        if (supportedAlgs != null && supportedAlgs.Count == 0)
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


        if (supportedAlgs != null)
        {
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
}