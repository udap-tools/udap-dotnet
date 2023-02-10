
namespace UdapEd.Shared.Model;
public class TokenResponseModel
{
    public bool IsError { get; set; }

    public string Error { get; set; }

    public string AccessToken { get; set; }

    public string IdentityToken { get; set; }

    public string RefreshToken { get; set; }

    public DateTime ExpiresAt { get; set; }

    public string Scope { get; set; }

    public string TokenType { get; set; }

    public string? Raw { get; set; }
}
