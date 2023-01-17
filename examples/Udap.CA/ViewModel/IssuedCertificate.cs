using System.Security.Cryptography.X509Certificates;

namespace Udap.CA.ViewModel;

public class IssuedCertificate
{
    public int Id { get; set; }
    public bool Enabled { get; set; }
    public string? Name { get; set; }
    public string? Community { get; set; }

    public X509Certificate2? Certificate { get; set; }
    public DateTime? BeginDate { get; set; }
    public DateTime? EndDate { get; set; }
}