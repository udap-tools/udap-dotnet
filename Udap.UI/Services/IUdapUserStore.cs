#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Duende.IdentityServer.Test;

namespace Udap.UI.Services;

/// <summary>
/// A user as the Udap.UI interaction services see it.
/// </summary>
public sealed record UdapUser(string SubjectId, string Username, IReadOnlyCollection<Claim> Claims);

/// <summary>
/// The user store the Udap.UI login and external-login services sign users in against.
/// Plug in a real identity store by registering an implementation before or after
/// <see cref="UdapUIServiceCollectionExtensions.AddUdapUI"/>; the default
/// <see cref="TestUserStoreAdapter"/> wraps Duende's in-memory <see cref="TestUserStore"/>.
/// </summary>
public interface IUdapUserStore
{
    /// <summary>Returns the user when the credentials are valid, otherwise null.</summary>
    Task<UdapUser?> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default);

    Task<UdapUser?> FindBySubjectAsync(string subjectId, CancellationToken cancellationToken = default);

    Task<UdapUser?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default);

    Task<UdapUser?> FindByExternalProviderAsync(string provider, string providerUserId, CancellationToken cancellationToken = default);

    /// <summary>Creates a local user for a first-time external login.</summary>
    Task<UdapUser> AutoProvisionAsync(string provider, string providerUserId, IReadOnlyCollection<Claim> claims, CancellationToken cancellationToken = default);
}

/// <summary>
/// Default <see cref="IUdapUserStore"/> over Duende's <see cref="TestUserStore"/>, matching the
/// behavior of the original sample pages.
/// </summary>
public class TestUserStoreAdapter : IUdapUserStore
{
    private readonly TestUserStore _users;

    public TestUserStoreAdapter(TestUserStore? users = null)
    {
        _users = users ?? throw new InvalidOperationException(
            "No IUdapUserStore is registered. Call 'AddTestUsers(TestUsers.Users)' on the IIdentityServerBuilder, " +
            "or register your own IUdapUserStore.");
    }

    public Task<UdapUser?> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_users.ValidateCredentials(username, password)
            ? Map(_users.FindByUsername(username))
            : null);
    }

    public Task<UdapUser?> FindBySubjectAsync(string subjectId, CancellationToken cancellationToken = default)
        => Task.FromResult(Map(_users.FindBySubjectId(subjectId)));

    public Task<UdapUser?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default)
        => Task.FromResult(Map(_users.FindByUsername(username)));

    public Task<UdapUser?> FindByExternalProviderAsync(string provider, string providerUserId, CancellationToken cancellationToken = default)
        => Task.FromResult(Map(_users.FindByExternalProvider(provider, providerUserId)));

    public Task<UdapUser> AutoProvisionAsync(string provider, string providerUserId, IReadOnlyCollection<Claim> claims, CancellationToken cancellationToken = default)
        => Task.FromResult(Map(_users.AutoProvisionUser(provider, providerUserId, claims.ToList()))!);

    private static UdapUser? Map(TestUser? user)
    {
        return user == null
            ? null
            : new UdapUser(user.SubjectId, user.Username, user.Claims?.ToList() ?? new List<Claim>());
    }
}
