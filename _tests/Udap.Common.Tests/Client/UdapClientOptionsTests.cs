#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Client.Configuration;
using Udap.Model;

namespace Udap.Common.Tests.Client;

public class UdapClientOptionsTests
{
    [Fact]
    public void DefaultConstructor_SetsDefaults()
    {
        var options = new UdapClientOptions();

        Assert.Equal(string.Empty, options.ClientName);
        Assert.NotNull(options.Contacts);
        Assert.Empty(options.Contacts);
        Assert.NotNull(options.Headers);
        Assert.Empty(options.Headers);
        Assert.Equal(string.Empty, options.TieredOAuthClientLogo);
        Assert.Equal(UdapConstants.UdapVersionsSupportedValue, options.UdapVersion);
    }

    [Fact]
    public void JsonConstructor_SetsAllProperties()
    {
        var contacts = new HashSet<string> { "mailto:joe@example.com" };
        var headers = new Dictionary<string, string> { { "USER_KEY", "joe" } };

        var options = new UdapClientOptions(
            clientName: "Test Client",
            contacts: contacts,
            headers: headers,
            tieredOAuthClientLogo: "https://example.com/logo.png",
            udapVersion: "1");

        Assert.Equal("Test Client", options.ClientName);
        Assert.Contains("mailto:joe@example.com", options.Contacts!);
        Assert.Equal("joe", options.Headers!["USER_KEY"]);
        Assert.Equal("https://example.com/logo.png", options.TieredOAuthClientLogo);
        Assert.Equal("1", options.UdapVersion);
    }

    [Fact]
    public void JsonConstructor_NullParameters_DefaultToEmpty()
    {
        var options = new UdapClientOptions(
            clientName: null,
            contacts: null,
            headers: null);

        Assert.Equal(string.Empty, options.ClientName);
        Assert.NotNull(options.Contacts);
        Assert.Empty(options.Contacts);
        Assert.NotNull(options.Headers);
        Assert.Empty(options.Headers);
        Assert.Equal(UdapConstants.UdapVersionsSupportedValue, options.UdapVersion);
    }
}
