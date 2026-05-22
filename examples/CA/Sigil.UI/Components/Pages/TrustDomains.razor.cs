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
using Microsoft.FluentUI.AspNetCore.Components;
using Sigil.Common.Services;
using Sigil.Common.ViewModels;

namespace Sigil.UI.Components.Pages;

public partial class TrustDomains
{
    [Inject] private TrustDomainService TrustDomainService { get; set; } = null!;
    [Inject] private NavigationManager Navigation { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;

    [SupplyParameterFromQuery] public string? Action { get; set; }
    [SupplyParameterFromQuery] public int? Edit { get; set; }

    private List<TrustDomainViewModel> trustDomains = new();
    private bool addDialogHidden = true;
    private string newTrustDomainName = string.Empty;
    private string newTrustDomainDescription = string.Empty;
    private int newTrustDomainExpiry = 7;
    private List<BaseUrlEntry> newTrustDomainBaseUrls = new();

    // Edit dialog
    private bool editDialogHidden = true;
    private int editTrustDomainId;
    private string editTrustDomainName = string.Empty;
    private string editTrustDomainDescription = string.Empty;
    private int editTrustDomainExpiry = 7;
    private List<BaseUrlEntry> editTrustDomainBaseUrls = new();

    // Folder browser
    private bool folderBrowserHidden = true;
    private string appBasePath = Directory.GetCurrentDirectory();
    private string folderBrowserCurrentPath = string.Empty;
    private string? folderBrowserSelectedSubdir;
    private List<string> folderBrowserSubdirectories = new();
    private bool folderBrowserUseRelative = true;
    private BaseUrlEntry? folderBrowserTarget;

    private string folderBrowserDisplayPath
    {
        get
        {
            var selected = folderBrowserSelectedSubdir ?? folderBrowserCurrentPath;
            if (string.IsNullOrEmpty(selected)) return string.Empty;
            if (folderBrowserUseRelative)
                return Path.GetRelativePath(appBasePath, selected);
            return selected;
        }
    }

    protected override async Task OnInitializedAsync()
    {
        await LoadTrustDomainsAsync();
        if (Action == "new")
        {
            ShowAddDialog();
        }
        else if (Edit.HasValue)
        {
            var target = trustDomains.FirstOrDefault(c => c.Id == Edit.Value);
            if (target != null)
                ShowEditDialog(target);
        }
    }

    private async Task LoadTrustDomainsAsync()
    {
        trustDomains = await TrustDomainService.GetAllAsync();
    }

    private void ShowAddDialog()
    {
        newTrustDomainName = string.Empty;
        newTrustDomainDescription = string.Empty;
        newTrustDomainExpiry = 7;
        newTrustDomainBaseUrls = new List<BaseUrlEntry>();
        addDialogHidden = false;
    }

    private async Task AddTrustDomainAsync()
    {
        if (string.IsNullOrWhiteSpace(newTrustDomainName)) return;

        var baseUrls = newTrustDomainBaseUrls
            .Where(e => !string.IsNullOrWhiteSpace(e.Value))
            .Select(e => (e.Value, (string?)e.PublishingBasePath))
            .ToList();

        await TrustDomainService.CreateAsync(newTrustDomainName, newTrustDomainDescription, baseUrls, newTrustDomainExpiry);
        addDialogHidden = true;
        await LoadTrustDomainsAsync();
    }

    // Impact confirmation dialog state
    private bool impactDialogHidden = true;
    private string impactDialogTitle = "Confirm";
    private string impactDialogMessage = string.Empty;
    private string impactDialogConfirmLabel = "Confirm";
    private List<ImpactItem>? impactDialogImpacts;
    private Func<Task>? impactDialogOnConfirm;
    private bool impactDialogBusy;

    private async Task DeleteTrustDomainAsync(TrustDomainViewModel trustDomain)
    {
        var impacts = await TrustDomainService.GetDeletionImpactAsync(trustDomain.Id);
        impactDialogTitle = $"Delete trust domain '{trustDomain.Name}'?";
        impactDialogMessage = "All certificates, CRLs, and revocation records in this trust domain will be permanently deleted. This cannot be undone.";
        impactDialogConfirmLabel = "Delete Trust Domain";
        impactDialogImpacts = impacts;
        impactDialogOnConfirm = () => ConfirmDeleteTrustDomainAsync(trustDomain.Id);
        impactDialogBusy = false;
        impactDialogHidden = false;
    }

    private async Task ConfirmDeleteTrustDomainAsync(int trustDomainId)
    {
        await TrustDomainService.DeleteAsync(trustDomainId);
        await LoadTrustDomainsAsync();
    }

    private async Task OnImpactDialogConfirmAsync()
    {
        if (impactDialogOnConfirm == null) return;
        impactDialogBusy = true;
        StateHasChanged();
        try
        {
            await impactDialogOnConfirm();
        }
        finally
        {
            impactDialogHidden = true;
            impactDialogBusy = false;
        }
    }

    private void OnImpactDialogCancel() => impactDialogHidden = true;

    private void ShowEditDialog(TrustDomainViewModel trustDomain)
    {
        editTrustDomainId = trustDomain.Id;
        editTrustDomainName = trustDomain.Name;
        editTrustDomainDescription = trustDomain.Description ?? string.Empty;
        editTrustDomainExpiry = trustDomain.CrlValidityDays;
        editTrustDomainBaseUrls = trustDomain.BaseUrls
            .Select(u => new BaseUrlEntry { Value = u.Url, PublishingBasePath = u.PublishingBasePath ?? string.Empty })
            .ToList();
        editDialogHidden = false;
    }

    private async Task SaveEditAsync()
    {
        if (string.IsNullOrWhiteSpace(editTrustDomainName)) return;

        var baseUrls = editTrustDomainBaseUrls
            .Where(e => !string.IsNullOrWhiteSpace(e.Value))
            .Select(e => (e.Value, (string?)e.PublishingBasePath))
            .ToList();

        await TrustDomainService.UpdateAsync(editTrustDomainId, editTrustDomainName, editTrustDomainDescription, baseUrls, editTrustDomainExpiry);

        editDialogHidden = true;
        await LoadTrustDomainsAsync();
    }

    private void NavigateToExplorer(int trustDomainId)
    {
        Navigation.NavigateTo($"/explorer/{trustDomainId}");
    }

    // --- Folder Browser ---

    private void ShowFolderBrowser(BaseUrlEntry target)
    {
        folderBrowserTarget = target;
        folderBrowserUseRelative = true;

        if (!string.IsNullOrWhiteSpace(target.PublishingBasePath))
        {
            var resolved = Path.IsPathRooted(target.PublishingBasePath)
                ? target.PublishingBasePath
                : Path.GetFullPath(Path.Combine(appBasePath, target.PublishingBasePath));
            folderBrowserCurrentPath = Directory.Exists(resolved) ? resolved : appBasePath;
        }
        else
        {
            folderBrowserCurrentPath = appBasePath;
        }

        folderBrowserSelectedSubdir = null;
        LoadSubdirectories();
        folderBrowserHidden = false;
    }

    private void LoadSubdirectories()
    {
        try
        {
            folderBrowserSubdirectories = Directory.GetDirectories(folderBrowserCurrentPath)
                .OrderBy(d => Path.GetFileName(d), StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            folderBrowserSubdirectories = new();
        }
    }

    private void FolderBrowserNavigateUp()
    {
        var parent = Directory.GetParent(folderBrowserCurrentPath);
        if (parent != null)
        {
            folderBrowserCurrentPath = parent.FullName;
            folderBrowserSelectedSubdir = null;
            LoadSubdirectories();
        }
    }

    private void FolderBrowserSelectDir(string dir)
    {
        folderBrowserSelectedSubdir = dir;
    }

    private void FolderBrowserNavigateInto(string dir)
    {
        folderBrowserCurrentPath = dir;
        folderBrowserSelectedSubdir = null;
        LoadSubdirectories();
    }

    private void FolderBrowserConfirm()
    {
        if (folderBrowserTarget == null) return;

        var selected = folderBrowserSelectedSubdir ?? folderBrowserCurrentPath;
        folderBrowserTarget.PublishingBasePath = folderBrowserUseRelative
            ? Path.GetRelativePath(appBasePath, selected)
            : selected;

        folderBrowserHidden = true;
    }

    private class BaseUrlEntry
    {
        public string Value { get; set; } = string.Empty;
        public string PublishingBasePath { get; set; } = string.Empty;
    }
}
