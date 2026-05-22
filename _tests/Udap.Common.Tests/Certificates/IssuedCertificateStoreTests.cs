using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Udap.Common.Certificates;
using Udap.Common.Metadata;

namespace Udap.Common.Tests.Certificates;

public class IssuedCertificateStoreTests
{
    [Fact]
    public async Task Resolve_NonExistentFile_LogsWarningAndContinues()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    IssuedCerts = new List<IssuedCertFile>
                    {
                        new IssuedCertFile { FilePath = "nonexistent/path/cert.pfx", Password = "test" }
                    }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new IssuedCertificateStore(monitor, Substitute.For<ILogger<IssuedCertificateStore>>());
        await store.Resolve();

        Assert.Empty(store.IssuedCertificates);
    }

    [Fact]
    public async Task Resolve_NullFilePath_LogsWarningAndContinues()
    {
        var manifest = new UdapFileCertStoreManifest
        {
            Communities = new List<Community>
            {
                new Community
                {
                    Name = "test-community",
                    IssuedCerts = new List<IssuedCertFile>
                    {
                        new IssuedCertFile { FilePath = null }
                    }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<UdapFileCertStoreManifest>>();
        monitor.CurrentValue.Returns(manifest);

        var store = new IssuedCertificateStore(monitor, Substitute.For<ILogger<IssuedCertificateStore>>());
        await store.Resolve();

        Assert.Empty(store.IssuedCertificates);
    }
}
