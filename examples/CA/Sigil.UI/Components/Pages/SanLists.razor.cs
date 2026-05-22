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
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;

namespace Sigil.UI.Components.Pages;

public partial class SanLists
{
    [Inject] private SanListService SanListService { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    private List<SanList> sanLists = new();
    private bool dialogHidden = true;
    private bool isEditing;
    private int? editingId;

    private string editName = string.Empty;
    private string editDescription = string.Empty;
    private List<SanEntry> editEntries = new();

    private static readonly string[] sanTypeNames = ["URI", "DNS", "Email", "IP"];

    protected override async Task OnInitializedAsync()
    {
        await LoadAsync();
    }

    private async Task LoadAsync()
    {
        sanLists = await SanListService.GetAllAsync();
    }

    private void ShowAddDialog()
    {
        isEditing = false;
        editingId = null;
        editName = string.Empty;
        editDescription = string.Empty;
        editEntries.Clear();
        dialogHidden = false;
    }

    private void ShowEditDialog(SanList list)
    {
        isEditing = true;
        editingId = list.Id;
        editName = list.Name;
        editDescription = list.Description ?? string.Empty;
        editEntries = ParseItems(list.Items);
        dialogHidden = false;
    }

    private async Task SaveAsync()
    {
        if (string.IsNullOrWhiteSpace(editName)) return;

        var items = editEntries
            .Where(e => !string.IsNullOrWhiteSpace(e.Value))
            .Select(e => $"{e.Type}:{e.Value.Trim()}");

        var entity = new SanList
        {
            Id = editingId ?? 0,
            Name = editName.Trim(),
            Description = string.IsNullOrWhiteSpace(editDescription) ? null : editDescription.Trim(),
            Items = string.Join(";", items)
        };

        await SanListService.SaveAsync(entity);
        ToastService.ShowSuccess($"SAN list '{entity.Name}' saved.");
        dialogHidden = true;
        await LoadAsync();
    }

    private async Task DeleteSanListAsync(SanList list)
    {
        var dialog = await DialogService.ShowConfirmationAsync(
            $"Delete SAN list '{list.Name}'?",
            "Delete", "Cancel", "Confirm Delete");
        var result = await dialog.Result;

        if (!result.Cancelled)
        {
            await SanListService.DeleteAsync(list.Id);
            ToastService.ShowSuccess($"SAN list '{list.Name}' deleted.");
            await LoadAsync();
        }
    }

    private static int CountItems(string items) =>
        string.IsNullOrWhiteSpace(items) ? 0 :
        items.Split(';', StringSplitOptions.RemoveEmptyEntries).Length;

    private static List<SanEntry> ParseItems(string items)
    {
        var result = new List<SanEntry>();
        if (string.IsNullOrWhiteSpace(items)) return result;

        foreach (var part in items.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var colonIdx = part.IndexOf(':');
            if (colonIdx > 0)
            {
                result.Add(new SanEntry
                {
                    Type = part[..colonIdx],
                    Value = part[(colonIdx + 1)..]
                });
            }
        }

        return result;
    }

    private class SanEntry
    {
        public string Type { get; set; } = "URI";
        public string Value { get; set; } = string.Empty;
    }
}
