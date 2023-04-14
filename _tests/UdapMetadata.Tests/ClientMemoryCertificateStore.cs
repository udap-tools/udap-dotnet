using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Udap.Common.Certificates;
using Udap.Common.Models;

namespace UdapMetadata.Tests;
internal class ClientMemoryCertificateStore : ICertificateStore
{
    public ICollection<X509Certificate2> IntermediateCertificates { get; set; }
    public ICollection<Anchor> AnchorCertificates { get; set; }
    public ICollection<IssuedCertificate> IssuedCertificates { get; set; }
    public Task<ICertificateStore> Resolve()
    {
        throw new NotImplementedException();
    }
}
