#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityModel;
using Duende.IdentityServer.Test;
using Microsoft.Extensions.DependencyInjection;

namespace Udap.UI.Pages.Account.Login;

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

    /// <summary>
    /// Projects Duende <see cref="TestUser"/> entries into login-page helper buttons.
    /// The button label is the user's <c>name</c> claim, falling back to the username.
    /// </summary>
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

/// <summary>
/// Test accounts shown on the login page. Empty by default, so the helper is hidden unless the
/// host opts in via <see cref="TestAccountServiceCollectionExtensions.AddLoginTestAccounts"/>.
/// </summary>
public class TestAccountOptions
{
    public List<TestAccount> Accounts { get; set; } = new();
}

public static class TestAccountServiceCollectionExtensions
{
    /// <summary>
    /// Shows one fill-in button per test user on the login page.
    /// </summary>
    public static IServiceCollection AddLoginTestAccounts(this IServiceCollection services, IEnumerable<TestUser> users)
    {
        var accounts = TestAccount.FromTestUsers(users);
        services.Configure<TestAccountOptions>(options => options.Accounts = accounts);
        return services;
    }
}
