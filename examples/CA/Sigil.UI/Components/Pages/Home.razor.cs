#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Sigil.Common.Services;
using Sigil.Common.ViewModels;

namespace Sigil.UI.Components.Pages;

public partial class Home : IDisposable
{
    [Inject] private DashboardService DashboardService { get; set; } = null!;
    [Inject] private NavigationManager Navigation { get; set; } = null!;
    [Inject] private Services.TimeDisplayService TimeDisplay { get; set; } = null!;

    private bool isLoading = true;

    // Summary stats
    private int trustDomainCount;
    private int caCertCount;
    private int issuedCertCount;
    private int templateCount;

    // TrustDomain summaries
    private List<TrustDomainSummary> trustDomainSummaries = new();

    // Expiring / expired certs
    private List<CertRow> expiringCerts = new();
    private List<CertRow> expiredCerts = new();

    // Overdue CRLs
    private List<CrlRow> overdueCrls = new();

    // Revoked certs
    private int revokedCertCount;

    protected override async Task OnInitializedAsync()
    {
        TimeDisplay.OnChanged += StateHasChanged;
        await LoadDashboardAsync();
    }

    public void Dispose()
    {
        TimeDisplay.OnChanged -= StateHasChanged;
    }

    private async Task LoadDashboardAsync()
    {
        isLoading = true;
        StateHasChanged();

        var data = await DashboardService.GetDashboardAsync();

        trustDomainCount = data.TrustDomainCount;
        caCertCount = data.CaCertCount;
        issuedCertCount = data.IssuedCertCount;
        templateCount = data.TemplateCount;
        revokedCertCount = data.RevokedCertCount;
        trustDomainSummaries = data.TrustDomainSummaries;
        expiringCerts = data.ExpiringCerts;
        expiredCerts = data.ExpiredCerts;
        overdueCrls = data.OverdueCrls;

        isLoading = false;
        StateHasChanged();
    }

    private void NavigateToTrustDomain(int trustDomainId)
    {
        Navigation.NavigateTo($"/explorer/{trustDomainId}");
    }

    private void NavigateToCert(int trustDomainId, string thumbprint)
    {
        Navigation.NavigateTo($"/explorer/{trustDomainId}?thumbprint={thumbprint}");
    }

}
