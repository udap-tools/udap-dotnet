namespace Udap.Server.Entities;

public class RootCertificate : ICertificateValidateMarker
{
    public long Id { get; set; }

    public bool Enabled { get; set; }
    public string Name { get; set; }
    /// <summary>
    /// Base64 Der encoded
    /// </summary>
    public string X509Certificate { get; set; }
    public string Thumbprint { get; set; }
    public DateTime BeginDate { get; set; }
    public DateTime EndDate { get; set; }

    public List<Community> Communities { get; set; }
}