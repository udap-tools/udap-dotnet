#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;
using System.Text.RegularExpressions;
using Udap.Common;

namespace Udap.Common.Tests;

public class TracingTests
{
    [Fact]
    public void TraceNames_FollowNamingConvention()
    {
        Assert.Equal("Udap.Server", Tracing.TraceNames.Basic);
        Assert.Equal("Udap.Server.Stores", Tracing.TraceNames.Store);
        Assert.Equal("Udap.Server.Validation", Tracing.TraceNames.Validation);
        Assert.Equal("Udap.Server.Endpoints", Tracing.TraceNames.Endpoints);
    }

    [Fact]
    public void ValidationField_MatchesTraceNamesValidation()
    {
        Assert.Equal(Tracing.TraceNames.Validation, Tracing.Validation);
    }

    [Fact]
    public void ServiceVersion_IsMajorMinorBuildFormat()
    {
        var version = Tracing.ServiceVersion;

        Assert.Matches(@"^\d+\.\d+\.\d+$", version);
    }

    [Fact]
    public void StoreActivitySource_HasCorrectNameAndVersion()
    {
        var source = Tracing.StoreActivitySource;

        Assert.Equal(Tracing.TraceNames.Store, source.Name);
        Assert.Equal(Tracing.ServiceVersion, source.Version);
    }

    [Fact]
    public void ValidationActivitySource_HasCorrectNameAndVersion()
    {
        var source = Tracing.ValidationActivitySource;

        Assert.Equal(Tracing.TraceNames.Validation, source.Name);
        Assert.Equal(Tracing.ServiceVersion, source.Version);
    }

    [Fact]
    public void DiscoveryEndpointActivitySource_HasCorrectNameAndVersion()
    {
        var source = Tracing.DiscoveryEndpointActivitySource;

        Assert.Equal(Tracing.TraceNames.Endpoints, source.Name);
        Assert.Equal(Tracing.ServiceVersion, source.Version);
    }

    [Fact]
    public void ActivitySources_AreSingletonInstances()
    {
        Assert.Same(Tracing.StoreActivitySource, Tracing.StoreActivitySource);
        Assert.Same(Tracing.ValidationActivitySource, Tracing.ValidationActivitySource);
        Assert.Same(Tracing.DiscoveryEndpointActivitySource, Tracing.DiscoveryEndpointActivitySource);
    }

    [Fact]
    public void Properties_ContainExpectedConstants()
    {
        Assert.Equal("endpoint_type", Tracing.Properties.EndpointType);
        Assert.Equal("client_id", Tracing.Properties.ClientId);
        Assert.Equal("idp_base_url", Tracing.Properties.IdPBaseUrl);
        Assert.Equal("grant_type", Tracing.Properties.GrantType);
        Assert.Equal("scope", Tracing.Properties.Scope);
        Assert.Equal("resource", Tracing.Properties.Resource);
        Assert.Equal("origin", Tracing.Properties.Origin);
        Assert.Equal("scheme", Tracing.Properties.Scheme);
        Assert.Equal("type", Tracing.Properties.Type);
        Assert.Equal("id", Tracing.Properties.Id);
        Assert.Equal("scope_names", Tracing.Properties.ScopeNames);
        Assert.Equal("api_resource_names", Tracing.Properties.ApiResourceNames);
        Assert.Equal("Community_Name", Tracing.Properties.Community);
        Assert.Equal("CommunityId", Tracing.Properties.CommunityId);
        Assert.Equal("anchor_certificate", Tracing.Properties.AnchorCertificate);
        Assert.Equal("root_certificate", Tracing.Properties.RootCertificate);
    }
}
