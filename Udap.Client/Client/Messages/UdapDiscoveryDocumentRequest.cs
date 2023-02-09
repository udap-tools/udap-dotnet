// UdapModel is modeled after IdentityModel. See https://github.com/IdentityModel/IdentityModel
// 
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;

namespace Udap.Client.Client.Messages;

/// <summary>
/// Request for UDAP discovery document
/// </summary>
public class UdapDiscoveryDocumentRequest : ProtocolRequest
{
    /// <summary>
    /// Gets or sets the policy.
    /// </summary>
    /// <value>
    /// The policy.
    /// </value>
    public DiscoveryPolicy Policy { get; set; } = new();

    /// <summary>
    /// Optional community qualifier
    /// </summary>
    public string Community { get; set; }
}