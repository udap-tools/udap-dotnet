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
using Sigil.Common.Services.Jobs;

namespace Sigil.UI.Components.Pages;

public partial class Jobs : IDisposable
{
    [Inject] private IRecurringJobScheduler JobScheduler { get; set; } = null!;
    [Inject] private CrlGenerationService CrlGenerationService { get; set; } = null!;
    [Inject] private Services.TimeDisplayService TimeDisplay { get; set; } = null!;

    private bool isLoading = true;
    private List<CrlStatusRow> crlStatuses = new();
    private Dictionary<string, List<CrlStatusRow>> crlStatusesByTrustDomain = new();
    private List<RecurringJobRow> recurringJobs = new();

    protected override async Task OnInitializedAsync()
    {
        TimeDisplay.OnChanged += StateHasChanged;
        LoadRecurringJobs();
        await LoadCrlStatusesAsync();
        isLoading = false;
    }

    private void LoadRecurringJobs()
    {
        var jobs = JobScheduler.GetRecurringJobs();
        recurringJobs = jobs.Select(j => new RecurringJobRow
        {
            JobId = j.JobId,
            OriginalCron = j.CronExpression,
            EditableCron = j.CronExpression,
            LastExecution = j.LastExecution,
            NextExecution = j.NextExecution
        }).ToList();
    }

    private void SaveCron(RecurringJobRow row)
    {
        JobScheduler.UpdateCronExpression(row.JobId, row.EditableCron);
        row.OriginalCron = row.EditableCron;

        // Refresh to get updated next execution time
        LoadRecurringJobs();
        StateHasChanged();
    }

    private void TriggerJob(RecurringJobRow row)
    {
        JobScheduler.TriggerJob(row.JobId);

        // Refresh to reflect the trigger
        LoadRecurringJobs();
        StateHasChanged();
    }

    private async Task GenerateCrl(CrlStatusRow row)
    {
        row.IsGenerating = true;
        StateHasChanged();

        var result = await CrlGenerationService.GenerateCrlAsync(row.CaId);

        row.IsGenerating = false;

        // Refresh the data to show the new CRL
        await LoadCrlStatusesAsync();
        StateHasChanged();
    }

    private async Task LoadCrlStatusesAsync()
    {
        var summaries = await CrlGenerationService.GetCrlStatusesAsync();

        crlStatuses = summaries.Select(s => new CrlStatusRow
        {
            CaId = s.CaId,
            CaName = s.CaName,
            TrustDomainName = s.TrustDomainName,
            LatestCrlNumber = s.LatestCrlNumber,
            NextUpdate = s.NextUpdate,
            HasCrl = s.HasCrl,
            NeedsRenewal = s.NeedsRenewal,
            RevokedCount = s.RevokedCount
        }).ToList();

        crlStatusesByTrustDomain = crlStatuses
            .GroupBy(s => s.TrustDomainName)
            .OrderBy(g => g.Key)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    private class RecurringJobRow
    {
        public string JobId { get; init; } = string.Empty;
        public string OriginalCron { get; set; } = string.Empty;
        public string EditableCron { get; set; } = string.Empty;
        public string? LastExecution { get; init; }
        public string? NextExecution { get; init; }
    }

    private class CrlStatusRow
    {
        public int CaId { get; init; }
        public string CaName { get; init; } = string.Empty;
        public string TrustDomainName { get; init; } = string.Empty;
        public long? LatestCrlNumber { get; init; }
        public DateTime NextUpdate { get; init; }
        public bool HasCrl { get; init; }
        public bool NeedsRenewal { get; init; }
        public int RevokedCount { get; init; }
        public bool IsGenerating { get; set; }
    }

    public void Dispose()
    {
        TimeDisplay.OnChanged -= StateHasChanged;
    }
}
