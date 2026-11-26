#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Server.Configuration;

/// <summary>
/// Limits on where the server connects when a request or a certificate names the destination: the Tiered OAuth IdP
/// discovery fetch, the registration logo_uri fetch, and AIA/CRL downloads. Bound from the
/// <see cref="SectionName"/> configuration section.
/// </summary>
public class OutboundConnectionOptions
{
    /// <summary>The configuration section these options are bound from.</summary>
    public const string SectionName = "UdapOutboundConnections";

    /// <summary>
    /// Refuse connections to loopback, private, link-local, carrier-grade NAT, multicast and other non-public
    /// addresses. Defaults to true.
    /// </summary>
    public bool BlockNonPublicAddresses { get; set; } = true;

    /// <summary>
    /// Allow loopback addresses. When not set, loopback is allowed only when the host environment is Development.
    /// </summary>
    public bool? AllowLoopback { get; set; }

    /// <summary>
    /// Hosts that may resolve to non-public addresses, for example an IdP or CRL server inside the same network.
    /// Each entry is an exact host name or IP literal, optionally with a port ("crl.internal" or "idp.internal:8443").
    /// An entry without a port allows any port. Wildcards are not supported.
    /// </summary>
    public ICollection<string> AllowedPrivateHosts { get; set; } = new List<string>();
}
