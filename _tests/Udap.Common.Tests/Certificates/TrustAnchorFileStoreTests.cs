using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Common.Certificates;
using Udap.Common.Metadata;

namespace Udap.Common.Tests.Certificates;

public class TrustAnchorFileStoreTests
{
    [Fact]
    public async Task Resolve_NullAnchorFilePath_ThrowsInvalidOperation()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    Anchors = new List<AnchoFile> { new AnchoFile { FilePath = null } }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new TrustAnchorFileStore(monitor, Substitute.For<ILogger<TrustAnchorFileStore>>());

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.Resolve());
    }

    [Fact]
    public async Task Resolve_NonExistentAnchorFile_ThrowsFileNotFound()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    Anchors = new List<AnchoFile>
                    {
                        new AnchoFile { FilePath = "nonexistent/path/cert.cer" }
                    }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new TrustAnchorFileStore(monitor, Substitute.For<ILogger<TrustAnchorFileStore>>());

        await Assert.ThrowsAsync<FileNotFoundException>(() => store.Resolve());
    }

    [Fact]
    public async Task Resolve_After_Manifest_Change_Drops_Removed_Anchors()
    {
        static Community CommunityWithAnchor(string name) => new()
        {
            Name = name,
            Anchors = new List<AnchoFile> { new AnchoFile { FilePath = "CertStore/anchors/SureFhirLabs_CA.cer" } }
        };

        var before = new UdapFileCertStoreManifest
        {
            Communities = new List<Community> { CommunityWithAnchor("udap://one"), CommunityWithAnchor("udap://two") }
        };
        var after = new UdapFileCertStoreManifest
        {
            Communities = new List<Community> { CommunityWithAnchor("udap://one") }
        };

        Action<UdapFileCertStoreManifest, string?>? onChange = null;
        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(before);
        monitor.OnChange(Arg.Do<Action<UdapFileCertStoreManifest, string?>>(listener => onChange = listener));

        var store = new TrustAnchorFileStore(monitor, Substitute.For<ILogger<TrustAnchorFileStore>>());

        var resolved = await store.Resolve();
        Assert.Equal(2, resolved.AnchorCertificates.Count);

        monitor.CurrentValue.Returns(after);
        Assert.NotNull(onChange);
        onChange(after, null);

        resolved = await store.Resolve();
        var anchor = Assert.Single(resolved.AnchorCertificates);
        Assert.Equal("udap://one", anchor.Community);
    }
}
