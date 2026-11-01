#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.UI.Services;

/// <summary>
/// Return URL checks shared by the interaction services.
/// </summary>
public static class UdapReturnUrl
{
    /// <summary>
    /// Same rules as <c>IUrlHelper.IsLocalUrl</c>: an app-relative path ("/x" or "~/x") that is not
    /// protocol-relative ("//host", "/\host") and carries no control characters.
    /// </summary>
    public static bool IsLocalUrl(string? url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        if (url[0] == '/')
        {
            if (url.Length == 1)
            {
                return true;
            }

            if (url[1] == '/' || url[1] == '\\')
            {
                return false;
            }

            return !HasControlCharacter(url.AsSpan(1));
        }

        if (url[0] == '~' && url.Length > 1 && url[1] == '/')
        {
            if (url.Length == 2)
            {
                return true;
            }

            if (url[2] == '/' || url[2] == '\\')
            {
                return false;
            }

            return !HasControlCharacter(url.AsSpan(2));
        }

        return false;
    }

    private static bool HasControlCharacter(ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            if (char.IsControl(c))
            {
                return true;
            }
        }

        return false;
    }
}
