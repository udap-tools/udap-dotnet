namespace Udap.Common.Models;

public class TieredClient
{
    public int Id { get; set; }
    public string? ClientName { get; set; }
    public string? ClientId { get; set; }
    public string? IdPBaseUrl { get; set; }
    public string? RedirectUri { get; set; }

    public string? ClientUriSan { get; set; }

    public int CommunityId { get; set; }
    public bool Enabled { get; set; }

    public string? TokenEndpoint { get; set; }
}