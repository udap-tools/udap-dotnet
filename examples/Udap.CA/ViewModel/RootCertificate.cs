using System.Security.Cryptography.X509Certificates;
using static System.Net.WebRequestMethods;

namespace Udap.CA.ViewModel;

public class RootCertificate
{
    public int Id { get; set; }
    public int CommunityId { get; set; }
    public bool Enabled { get; set; }
    public string Name { get; set; } = string.Empty;
    public X509Certificate2? Certificate { get; set; }
    public string Secret { get; set; } = "udap-test";
    public string? Thumbprint { get; set; }
    /// <summary>
    /// Place where public certificate is hosted.
    /// </summary>
    public string Url { get; set; } = new Uri("http://crl.fhircerts.net/certs/SureFhirLabs_CA.cer").AbsoluteUri;
    public DateTime? BeginDate { get; set; } = DateTime.Now;
    public DateTime? EndDate { get; set; } = DateTime.Now.AddYears(10);
    public ICollection<Anchor>? Anchors { get; set; }
}