using Duende.IdentityModel;
using Duende.IdentityServer.Test;

namespace Udap.Identity.Provider.Pages.Login;

/// <summary>
/// A test credential surfaced on the login page so a tester does not have to remember it.
/// Clicking the account's button fills the username and password fields; the tester still
/// presses Login to continue.
/// </summary>
public class TestAccount
{
    public string DisplayName { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    public static List<TestAccount> FromTestUsers(IEnumerable<TestUser> users)
    {
        return (users ?? Enumerable.Empty<TestUser>())
            .Where(u => u.IsActive && !string.IsNullOrEmpty(u.Username) && !string.IsNullOrEmpty(u.Password))
            .Select(u => new TestAccount
            {
                Username = u.Username,
                Password = u.Password,
                DisplayName = u.Claims?.FirstOrDefault(c => c.Type == JwtClaimTypes.Name)?.Value ?? u.Username
            })
            .ToList();
    }
}
