#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;

namespace Udap.Server.Options;

public class UdapConfigurationStoreOptions : ConfigurationStoreOptions
{
    /// <summary>
    /// Callback to configure the EF DbContext.
    /// </summary>
    /// <value>
    /// The configure database context.
    /// </value>
    public Action<DbContextOptionsBuilder> UdapDbContext { get; set; } = default!;


    /// <summary>
    /// Gets or sets the anchors table configuration.
    /// </summary>
    /// <value>
    /// The client.
    /// </value>
    public TableConfiguration Anchor { get; set; } = new TableConfiguration("UdapAnchors");

    /// <summary>
    /// Gets or sets the RootCertificate table configuration.
    /// </summary>
    /// <value>
    /// The client.
    /// </value>
    public TableConfiguration IntermediateCertificate { get; set; } = new TableConfiguration("UdapIntermediateCertificates");


    /// <summary>
    /// Gets or sets the Community table configuration.
    /// </summary>
    /// <value>
    /// The client.
    /// </value>
    public TableConfiguration Community { get; set; } = new TableConfiguration("UdapCommunities");

    /// <summary>
    /// Gets or sets the Certification table configuration.
    /// </summary>
    /// <value>
    /// The client.
    /// </value>
    public TableConfiguration Certification { get; set; } = new TableConfiguration("UdapCertifications");

    /// <summary>
    /// Gets or sets the AnchorCertificationAssociate table configuration.
    /// </summary>
    /// <value>
    /// The client.
    /// </value>
    public TableConfiguration AnchorCertificationAssociate { get; set; } = new TableConfiguration("UdapAnchorCertification");

    /// <summary>
    /// Gets or sets the AnchorCertificationAssociate table configuration.
    /// </summary>
    /// <value>
    /// The client.
    /// </value>
    public TableConfiguration CommunityCertificationAssociate { get; set; } = new TableConfiguration("UdapCommunityCertification");
}

