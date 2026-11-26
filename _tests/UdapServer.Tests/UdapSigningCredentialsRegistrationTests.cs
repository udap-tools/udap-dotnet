#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Udap.Common.Certificates;
using Udap.Common.Models;
using Udap.Model;

namespace UdapServer.Tests;

/// <summary>
/// AddUdapSigningCredentials: the issued certificates become IdentityServer signing credentials and validation keys with
/// their community's algorithms, whatever else has or has not loaded the certificate store first.
/// </summary>
public class UdapSigningCredentialsRegistrationTests
{
    private const string Community = "udap://signing.test/";

    [Fact]
    public async Task Waits_For_The_Certificate_Store_Before_Reading_It()
    {
        // The store loads asynchronously (as a Vault- or file-backed store does). Reading IssuedCertificates before the
        // load completes used to register no credentials, or, once something else had loaded the store, throw.
        var store = new SlowStore(TimeSpan.FromMilliseconds(300), Issued(Community));
        await using var provider = Build(store, Configuration(Community));

        var validation = provider.GetRequiredService<IEnumerable<IValidationKeysStore>>().ToList();
        var signing = provider.GetRequiredService<IEnumerable<ISigningCredentialStore>>().ToList();

        Assert.NotEmpty(validation);
        Assert.NotEmpty(signing);
        Assert.True(store.Loads >= 1); // each registration resolves; real stores load once and return the loaded set after
    }

    [Fact]
    public async Task Uses_The_Algorithms_From_The_Bound_UdapMetadataOptions_Section()
    {
        var store = new SlowStore(TimeSpan.Zero, Issued(Community));
        await using var provider = Build(store, Configuration(Community, "RS384"));

        var keys = new List<Duende.IdentityServer.Models.SecurityKeyInfo>();
        foreach (var keyStore in provider.GetRequiredService<IEnumerable<IValidationKeysStore>>())
        {
            keys.AddRange(await keyStore.GetValidationKeysAsync(CancellationToken.None));
        }

        var key = Assert.Single(keys);
        Assert.Equal("RS384", key.SigningAlgorithm);
    }

    [Fact]
    public async Task An_Issued_Certificate_Whose_Community_Has_No_Config_Fails_Naming_The_Community()
    {
        var store = new SlowStore(TimeSpan.Zero, Issued(Community));
        await using var provider = Build(store, Configuration("udap://some-other-community/"));

        var error = Assert.Throws<InvalidOperationException>(() =>
            provider.GetRequiredService<IEnumerable<IValidationKeysStore>>());

        Assert.Contains(Community, error.Message);
        Assert.Contains("UdapMetadataConfigs", error.Message);
    }

    [Fact]
    public async Task A_Store_That_Does_Not_Load_In_Time_Fails_With_The_Timeout()
    {
        var store = new SlowStore(Timeout.InfiniteTimeSpan, Issued(Community));
        await using var provider = Build(store, Configuration(Community, timeoutSeconds: 1));

        var error = Assert.Throws<InvalidOperationException>(() =>
            provider.GetRequiredService<IEnumerable<ISigningCredentialStore>>());

        Assert.Contains("timed out after 1 seconds", error.Message);
    }

    private static ServiceProvider Build(IPrivateCertificateStore store, IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddSingleton(configuration);
        services.AddSingleton(store);
        services.AddUdapServerBuilder().AddUdapSigningCredentials<UdapMetadataOptions>();
        return services.BuildServiceProvider();
    }

    private static IConfiguration Configuration(string community, string? algorithm = null, int timeoutSeconds = 10)
    {
        var values = new Dictionary<string, string?>
        {
            ["UdapMetadataOptions:CertificateResolveTimeoutSeconds"] = timeoutSeconds.ToString(),
            ["UdapMetadataOptions:UdapMetadataConfigs:0:Community"] = community,
            ["UdapMetadataOptions:UdapMetadataConfigs:0:SignedMetadataConfig:Issuer"] = "https://signing.test",
        };
        if (algorithm != null)
        {
            values["UdapMetadataOptions:UdapMetadataConfigs:0:SignedMetadataConfig:TokenSigningAlgorithms:0"] = algorithm;
        }
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private static IssuedCertificate Issued(string community)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=signing.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return new IssuedCertificate(X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), null), community);
    }

    /// <summary>A certificate store whose load completes after <c>delay</c>, honouring cancellation.</summary>
    private sealed class SlowStore(TimeSpan delay, IssuedCertificate issued) : IPrivateCertificateStore
    {
        private int _loads;
        public int Loads => Volatile.Read(ref _loads);

        public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new HashSet<IssuedCertificate>();

        public async Task<IPrivateCertificateStore> Resolve(CancellationToken token)
        {
            if (delay != TimeSpan.Zero)
            {
                await Task.Delay(delay, token);
            }
            IssuedCertificates = new HashSet<IssuedCertificate> { issued };
            Interlocked.Increment(ref _loads);
            return this;
        }
    }
}
