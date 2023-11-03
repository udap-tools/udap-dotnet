namespace Udap.Common.Models;

public class TieredClient
{
    public int Id { get; set; }
    public string ClientName { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string IdPBaseUrl { get; set; } = default!;
    public string RedirectUri { get; set; } = default!;

    public string ClientUriSan { get; set; } = default!;

    public int CommunityId { get; set; }
    public bool Enabled { get; set; }

    public string TokenEndpoint { get; set; }
}