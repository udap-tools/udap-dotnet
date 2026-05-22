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
}
