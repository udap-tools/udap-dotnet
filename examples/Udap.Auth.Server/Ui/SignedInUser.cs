#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;

namespace Udap.Auth.Server.Ui;

/// <summary>How SecuredControls Auth names the signed-in person on its pages.</summary>
public static class SignedInUser
{
    /// <summary>
    /// The person's name from their session: the <c>name</c> claim, else given + family name, else the
    /// username, else the subject id.
    /// </summary>
    public static string DisplayName(ClaimsPrincipal user)
    {
        var name = user.FindFirst("name")?.Value;
        if (!string.IsNullOrWhiteSpace(name))
        {
            return name;
        }

        var parts = new[] { user.FindFirst("given_name")?.Value, user.FindFirst("family_name")?.Value }
            .Where(v => !string.IsNullOrWhiteSpace(v));
        var full = string.Join(' ', parts);
        if (!string.IsNullOrWhiteSpace(full))
        {
            return full;
        }

        return user.Identity?.Name ?? user.FindFirst("sub")?.Value ?? "you";
    }
}
