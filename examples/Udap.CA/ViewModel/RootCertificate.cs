using System.Security.Cryptography.X509Certificates;

namespace Udap.CA.ViewModel;

public class RootCertificate
{
    public int Id { get; set; }
    public bool Enabled { get; set; }
    public string Name { get; set; } = string.Empty;
    public X509Certificate2? Certificate { get; set; }
    public string? Thumbprint { get; set; }
    /// <summary>
    /// Place where public certificate is hosted.
    /// </summary>
    public Uri Url { get; set; }
    public DateTime? BeginDate { get; set; }
    public DateTime? EndDate { get; set; }
    public ICollection<Anchor>? Anchors { get; set; }
}