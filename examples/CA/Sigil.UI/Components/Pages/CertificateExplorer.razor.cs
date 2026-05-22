#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.FluentUI.AspNetCore.Components;
using Microsoft.JSInterop;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services;
using Sigil.Common.Services.Jobs;
using Sigil.Common.Services.Signing;
using Sigil.Common.ViewModels;
using Sigil.Gcp;
using Sigil.UI.Services;
using Sigil.Vault;

namespace Sigil.UI.Components.Pages;

public partial class CertificateExplorer : IDisposable
{
    [Parameter] public int TrustDomainId { get; set; }
    [SupplyParameterFromQuery(Name = "thumbprint")] public string? SelectedThumbprint { get; set; }

    [Inject] private IDbContextFactory<SigilDbContext> DbFactory { get; set; } = null!;
    [Inject] private CertificateParsingService ParsingService { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;
    [Inject] private IDialogService DialogService { get; set; } = null!;
    [Inject] private Asn1ParsingService Asn1Parser { get; set; } = null!;
    [Inject] private CrlImportService CrlImporter { get; set; } = null!;
    [Inject] private ChainValidationService ChainValidator { get; set; } = null!;
    [Inject] private CertificateIssuanceService IssuanceService { get; set; } = null!;
    [Inject] private CertificateExportService ExportService { get; set; } = null!;
    [Inject] private CertificateManagementService ManagementService { get; set; } = null!;
    [Inject] private CertificatePublishingService PublishingService { get; set; } = null!;
    [Inject] private CertificateImportService ImportService { get; set; } = null!;
    [Inject] private ISigningProvider SigningProvider { get; set; } = null!;
    [Inject] private VaultTransitSigningProvider VaultTransitProvider { get; set; } = null!;
    [Inject] private GcpKmsSigningProvider GcpKmsProvider { get; set; } = null!;
    [Inject] private IOptions<SigningProviderOptions> SigningOptions { get; set; } = null!;
    [Inject] private IHttpClientFactory HttpClientFactory { get; set; } = null!;
    [Inject] private IJSRuntime JS { get; set; } = null!;
    [Inject] private NavigationManager Navigation { get; set; } = null!;
    [Inject] private CrlGenerationService CrlGenService { get; set; } = null!;
    [Inject] private TimeDisplayService TimeDisplay { get; set; } = null!;
    [Inject] private IssuancePasswordCache PasswordCache { get; set; } = null!;

    // Tree state
    private List<TrustDomainOption> trustDomainList = new();
    private TrustDomainOption? selectedTrustDomain;
    private string selectedTrustDomainName = string.Empty;
    private List<CertificateChainNodeViewModel> treeNodes = new();

    // Tree filter
    private bool treeFilterExpanded;
    private string treeFilterText = string.Empty;
    private TreeStatusFilterOption selectedTreeStatusFilter = new("All", null);
    private static readonly List<TreeStatusFilterOption> treeStatusFilterOptions = new()
    {
        new("All", null),
        new("Valid", CertificateStatus.Valid),
        new("Expiring", CertificateStatus.Expiring),
        new("Expired", CertificateStatus.Expired),
        new("Revoked", CertificateStatus.Revoked),
        new("Untrusted", CertificateStatus.Untrusted),
        new("Superseded CA", CertificateStatus.Stale),
        new("CRLs only", null, "CRL"),
    };
    private HashSet<CertificateChainNodeViewModel> visibleNodes = new();
    private int visibleNodeCount;
    private int totalNodeCount;
    private bool IsTreeFilterActive =>
        !string.IsNullOrWhiteSpace(treeFilterText)
        || selectedTreeStatusFilter.Value != null
        || selectedTreeStatusFilter.RoleOnly != null;

    private CertificateChainNodeViewModel? selectedNode;
    private X509Certificate2? selectedCert;
    private Asn1Node? asn1Root;
    private CrlViewModel? selectedCrl;
    private ChainValidationResult? chainValidation;
    private bool selectedNodeHasPrivateKey;
    private bool selectedNodeHasRemoteKey;
    private bool selectedNodeCanSign => selectedNodeHasPrivateKey || selectedNodeHasRemoteKey;
    private bool selectedNodeAutoRenew = true;
    private bool isGeneratingCrl;
    private bool isPublishingAia;
    private bool crlOverrideDialogHidden = true;
    private DateTime? crlOverrideNextUpdate;
    private List<string> subjectAltNames = new();
    private FluentTreeItem? selectedTreeItem;
    private int treeVersion;
    private bool isLoadingTree;
    private bool isRevalidating;
    private bool isValidatingOnline;
    private bool pendingHighlight;
    private Dictionary<string, ChainValidationResult> trustDomainValidations = new();

    // Rename state
    private bool isRenaming;
    private string renamingValue = string.Empty;

    // Import state
    private bool showDropZone;
    private string? importError;
    private List<string> importErrors = new();
    private bool isImportingBatch;
    private int importProgress;
    private int importTotal;
    private FluentInputFile? fileInput;
    private InputFile? folderInput;
    private Queue<(byte[] Bytes, string FileName)> pendingPasswordQueue = new();

    // Password dialog
    private bool passwordDialogHidden = true;
    private string pfxPassword = string.Empty;
    private string? passwordError;
    private string pendingFileName = string.Empty;
    private byte[]? pendingFileBytes;

    // Move dialog
    private bool moveDialogHidden = true;
    private TrustDomainOption? moveTargetTrustDomain;

    // Confirm dialog
    private bool confirmDialogHidden = true;
    private ParsedCertificate? parsedCert;
    private string importName = string.Empty;
    private string? chainMatchDescription;
    private int? matchedParentCaId;

    // CA selection dialog (for unmatched certs)
    private bool caSelectDialogHidden = true;
    private List<CaSelectOption> availableCas = new();
    private CaSelectOption? selectedCaForAssignment;
    private ParsedCertificate? pendingCaSelectParsed;
    private Queue<(byte[] Bytes, string FileName, string? Password)> pendingCaSelectQueue = new();

    // Issuance dialog
    private bool issuanceDialogHidden = true;
    private bool isIssuing;
    private int? issuingCaIdForIssuance;
    private string? issuingCaNameForIssuance;
    private DateTime? issuingCaNotAfter;
    private List<CertificateTemplate> availableTemplates = new();
    private CertificateTemplate? selectedTemplate;
    private string issuanceSubjectDn = string.Empty;
    private string issuanceCertName = string.Empty;
    private DateTime? issuanceNotBeforeNullable = DateTime.UtcNow;
    private DateTime? issuanceNotAfterNullable = DateTime.UtcNow.AddYears(1);
    private List<IssuanceUrlEntry> issuanceCdpUrls = new();
    private List<IssuanceUrlEntry> issuanceAiaUrls = new();
    private List<IssuanceSanEntry> issuanceSans = new();
    private List<SanList> templateSanLists = new();
    private bool sanPickerDialogHidden = true;
    private SanList? sanListForPicker;
    private List<SanListPickerItem> sanPickerItems = new();
    private bool sanPickerSelectAll;
    private string issuancePfxPassword = string.Empty;
    private bool rememberIssuancePassword;
    private string issuanceKeyStorage = "local";
    private List<string> availableKeyStorageProviders = new() { "local" };
    private bool isRenewMode;
    private List<IssuanceSanEntry> renewalSans = new();
    private string renewalSubjectDn = string.Empty;
    private List<string> renewalOriginalCdpUrls = new();
    private List<string> renewalOriginalAiaUrls = new();
    private List<string> urlChangeWarnings = new();
    private bool noBaseUrlsWarning;

    // Impact confirmation dialog (shared by delete / revoke flows)
    private bool impactDialogHidden = true;
    private string impactDialogTitle = "Confirm";
    private string impactDialogMessage = string.Empty;
    private string impactDialogConfirmLabel = "Confirm";
    private List<ImpactItem>? impactDialogImpacts;
    private Func<Task>? impactDialogOnConfirm;
    private bool impactDialogBusy;

    // Revoke dialog
    private bool revokeDialogHidden = true;
    private List<ImpactItem>? revokeImpacts;
    private bool isRevoking;
    private RevokeReasonOption selectedRevokeReason = null!;
    private static readonly List<RevokeReasonOption> revokeReasonOptions = new()
    {
        new(0, "Unspecified"),
        new(1, "Key Compromise"),
        new(2, "CA Compromise"),
        new(3, "Affiliation Changed"),
        new(4, "Superseded"),
        new(5, "Cessation of Operation"),
        new(9, "Privilege Withdrawn"),
    };

    // Tree context menu
    private bool contextMenuOpen;
    private int contextMenuX;
    private int contextMenuY;
    private CertificateChainNodeViewModel? contextMenuNode;

    // Re-sign dialog
    private bool resignDialogHidden = true;
    private bool isResigning;
    private DateTime? resignNotBefore = DateTime.UtcNow;
    private DateTime? resignNotAfter = DateTime.UtcNow.AddYears(5);
    private string resignPfxPassword = string.Empty;
    private DotNetObjectReference<CertificateExplorer>? dotNetRef;
    private bool pendingDragDropInit;

    protected override async Task OnInitializedAsync()
    {
        TimeDisplay.OnChanged += StateHasChanged;

        availableKeyStorageProviders = SigningOptions.Value.AvailableProviders;

        await using var db = await DbFactory.CreateDbContextAsync();

        trustDomainList = await db.TrustDomains
            .OrderBy(c => c.Name)
            .Select(c => new TrustDomainOption
            {
                Id = c.Id,
                Name = c.Name,
                BaseUrls = c.BaseUrls.OrderBy(bu => bu.SortOrder)
                    .Select(bu => new BaseUrlViewModel { Url = bu.Url, PublishingBasePath = bu.PublishingBasePath })
                    .ToList()
            })
            .ToListAsync();

        if (TrustDomainId > 0)
        {
            selectedTrustDomain = trustDomainList.FirstOrDefault(c => c.Id == TrustDomainId);
            await LoadTrustDomainTreeAsync(TrustDomainId);

            // Auto-select cert if thumbprint was provided via query string
            if (!string.IsNullOrEmpty(SelectedThumbprint))
            {
                var node = FindNodeByThumbprint(treeNodes, SelectedThumbprint);
                if (node != null)
                {
                    await SelectNode(node);
                    pendingHighlight = true;
                }

                // Clear the query string so it doesn't linger as the user navigates
                SelectedThumbprint = null;
                Navigation.NavigateTo($"/explorer/{TrustDomainId}", replace: true);
            }
        }
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            dotNetRef ??= DotNetObjectReference.Create(this);
            await JS.InvokeVoidAsync("sigilInitTreeContextMenu", dotNetRef);
        }

        if (pendingHighlight)
        {
            pendingHighlight = false;
            await UpdateTreeHighlightsAsync();
        }

        if (pendingDragDropInit)
        {
            pendingDragDropInit = false;
            await InitDragDropAsync();
        }
    }

    [JSInvokable]
    public async Task OnTreeContextMenuAsync(string elementId, int x, int y)
    {
        CertificateChainNodeViewModel? node = null;
        if (elementId.StartsWith("tree-crl-", StringComparison.Ordinal))
        {
            if (int.TryParse(elementId["tree-crl-".Length..], out var crlId))
                node = FindNodeById(treeNodes, crlId, "Crl");
        }
        else if (elementId.StartsWith("tree-", StringComparison.Ordinal))
        {
            var thumbprint = elementId["tree-".Length..];
            node = FindNodeByThumbprint(treeNodes, thumbprint);
        }
        if (node == null) return;

        // Load the node first so selectedNodeCanSign / selectedNodeHasPrivateKey are correct
        // by the time the menu paints — otherwise CA-only items (Regen CRL, Publish AIA…)
        // are hidden because they're gated on stale selection state from the previous click.
        contextMenuNode = node;
        contextMenuX = x;
        contextMenuY = y;
        await SelectNode(node);
        contextMenuOpen = true;
        StateHasChanged();
    }

    private async Task InitDragDropAsync()
    {
        dotNetRef ??= DotNetObjectReference.Create(this);

        var dragItems = new List<object>();
        var dropTargets = new List<object>();

        CollectDragDropNodes(treeNodes, dragItems, dropTargets);

        if (dragItems.Count > 0)
        {
            await JS.InvokeVoidAsync("sigilInitDragDrop", dotNetRef, dragItems, dropTargets);
        }
    }

    private static void CollectDragDropNodes(
        List<CertificateChainNodeViewModel> nodes,
        List<object> dragItems,
        List<object> dropTargets)
    {
        foreach (var node in nodes)
        {
            if (node.EntityType == "IssuedCertificate" && node.Status == CertificateStatus.Stale)
            {
                dragItems.Add(new { thumbprint = node.Thumbprint, id = node.Id, entityType = node.EntityType });
            }

            if (node.EntityType == "CaCertificate" && node.KeyStorage != null && !node.IsSuperseded)
            {
                dropTargets.Add(new { thumbprint = node.Thumbprint, id = node.Id, name = node.Name });
            }

            CollectDragDropNodes(node.Children, dragItems, dropTargets);
        }
    }

    [JSInvokable]
    public async Task OnDragDropRenew(int certId, string entityType, int targetCaId, string targetCaName)
    {
        var node = FindNodeById(treeNodes, certId, entityType);
        if (node == null) return;

        await SelectNode(node);

        renewalOriginalCdpUrls = ExtractExtensionUrls(selectedCert, "2.5.29.31");
        renewalOriginalAiaUrls = ExtractExtensionUrls(selectedCert, "1.3.6.1.5.5.7.1.1");
        urlChangeWarnings.Clear();

        renewalSubjectDn = selectedCert?.Subject ?? string.Empty;
        renewalSans.Clear();
        foreach (var san in subjectAltNames)
        {
            var trimmed = san.Trim();
            if (TryParseSan(trimmed, "URL=", SanType.Uri, out var entry) ||
                TryParseSan(trimmed, "URI:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "Uri:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "DNS Name=", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "DNS:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "Dns:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "RFC822 Name=", SanType.Email, out entry) ||
                TryParseSan(trimmed, "email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "Email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "IP Address=", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IP:", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IpAddress:", SanType.IpAddress, out entry))
            {
                renewalSans.Add(entry);
            }
        }

        isRenewMode = true;
        await ShowIssuanceDialog(targetCaId, targetCaName);
        isRenewMode = true;

        // Match template from original cert
        await using var db = await DbFactory.CreateDbContextAsync();
        var issued = await db.IssuedCertificates.FindAsync(certId);
        if (issued?.TemplateId != null)
        {
            var match = availableTemplates.FirstOrDefault(t => t.Id == issued.TemplateId);
            if (match != null)
            {
                selectedTemplate = match;
                OnTemplateSelected(match);
            }
        }

        if (selectedTemplate == null || selectedTemplate.CertificateType != CertificateType.EndEntityClient)
        {
            var match = availableTemplates.FirstOrDefault(t => t.CertificateType == CertificateType.EndEntityClient)
                        ?? availableTemplates.FirstOrDefault();
            if (match != null) selectedTemplate = match;
        }

        OnTemplateSelected(selectedTemplate);
        if (selectedTemplate != null)
            await EnsureTemplateSanListsLoadedAsync(selectedTemplate);
        issuanceCertName = node.Name + " (renewed)";
        StateHasChanged();
    }

    private static CertificateChainNodeViewModel? FindNodeById(
        List<CertificateChainNodeViewModel> nodes, int id, string entityType)
    {
        foreach (var node in nodes)
        {
            if (node.Id == id && node.EntityType == entityType) return node;
            var found = FindNodeById(node.Children, id, entityType);
            if (found != null) return found;
        }
        return null;
    }

    private async Task OnTrustDomainSelected(TrustDomainOption? option)
    {
        if (option != null)
        {
            selectedTrustDomain = option;
            TrustDomainId = option.Id;
            await LoadTrustDomainTreeAsync(option.Id);
        }
    }

    private async Task LoadTrustDomainTreeAsync(int trustDomainId)
    {
        isLoadingTree = true;
        StateHasChanged();

        var treeData = await ManagementService.GetTrustDomainTreeAsync(trustDomainId);

        selectedTrustDomainName = treeData.TrustDomainName;
        trustDomainValidations = treeData.Validations;
        treeNodes = treeData.TreeNodes;
        RecomputeVisibleNodes();

        // Background check: validate Vault Transit-signed nodes' keys still exist
        _ = CheckRemoteKeysAsync(treeNodes);

        treeVersion++;
        selectedTreeItem = null;
        selectedNode = null;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        chainValidation = null;
        asn1Root = null;
        subjectAltNames.Clear();
        isLoadingTree = false;
        pendingDragDropInit = true;
    }


    // --- Tree selection ---

    private async Task OnTreeItemSelected(FluentTreeItem? item)
    {
        selectedTreeItem = item;
        isRenaming = false;

        if (item?.Data is CertificateChainNodeViewModel node)
        {
            await SelectNode(node);
        }
    }

    private async Task SelectNode(CertificateChainNodeViewModel node)
    {
        selectedNode = node;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        selectedNodeHasPrivateKey = false;
        selectedNodeHasRemoteKey = false;
        selectedNodeAutoRenew = true;
        chainValidation = null;
        asn1Root = null;
        subjectAltNames.Clear();
        CloseIssuerDetails();

        // CRL selection still uses DbFactory (CRL detail view is UI-specific)
        if (node.EntityType == "Crl")
        {
            await using var db = await DbFactory.CreateDbContextAsync();
            var crl = await db.Crls
                .Include(c => c.CaCertificate)
                .Include(c => c.Revocations)
                .FirstOrDefaultAsync(c => c.Id == node.Id);

            if (crl != null)
            {
                selectedCrl = new CrlViewModel
                {
                    Id = crl.Id,
                    CaCertificateId = crl.CaCertificateId,
                    CaName = crl.CaCertificate.Name,
                    CrlNumber = crl.CrlNumber,
                    ThisUpdate = crl.ThisUpdate,
                    NextUpdate = crl.NextUpdate,
                    SignatureAlgorithm = crl.SignatureAlgorithm,
                    SignatureValid = crl.SignatureValid,
                    FileName = crl.FileName,
                    Thumbprint = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(crl.RawBytes)),
                    AuthorityKeyIdentifier = ExtractCrlAki(crl.RawBytes),
                    RevokedCount = crl.Revocations.Count,
                    ImportedAt = crl.ImportedAt,
                    RevokedCertificates = crl.Revocations
                        .OrderBy(r => r.RevocationDate)
                        .Select(r => new RevokedCertEntry
                        {
                            SerialNumber = r.RevokedCertSerialNumber,
                            Thumbprint = r.RevokedCertThumbprint,
                            RevocationDate = r.RevocationDate,
                            ReasonCode = r.RevocationReason
                        })
                        .ToList()
                };

                asn1Root = Asn1Parser.Parse(crl.RawBytes);
            }

            return;
        }

        var details = await ManagementService.GetNodeDetailsAsync(node.Id, node.EntityType);
        selectedNodeHasPrivateKey = details.HasPrivateKey;
        selectedNodeHasRemoteKey = details.HasRemoteKey;
        selectedNodeAutoRenew = details.AutoRenew;

        if (!string.IsNullOrEmpty(details.Pem))
        {
            try
            {
                selectedCert = X509Certificate2.CreateFromPem(details.Pem);
                asn1Root = Asn1Parser.ParsePem(details.Pem);

                if (!string.IsNullOrEmpty(node.Thumbprint)
                    && trustDomainValidations.TryGetValue(node.Thumbprint, out var cached))
                {
                    chainValidation = cached;
                }
                else
                {
                    if (node.EntityType == "CaCertificate")
                        chainValidation = await ChainValidator.ValidateCaCertificateAsync(node.Id);
                    else
                        chainValidation = await ChainValidator.ValidateIssuedCertificateAsync(node.Id);
                }
            }
            catch { }
        }

        if (!string.IsNullOrEmpty(details.SubjectAltNames))
        {
            subjectAltNames = details.SubjectAltNames.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        }
        else if (selectedCert != null)
        {
            var sanExt = selectedCert.Extensions["2.5.29.17"];
            if (sanExt != null)
            {
                try
                {
                    subjectAltNames = sanExt.Format(multiLine: true)
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                }
                catch { }
            }
        }

        await UpdateTreeHighlightsAsync();
    }

    private async Task CopySubjectDnAsync()
    {
        var dn = contextMenuNode?.Subject ?? contextMenuNode?.Name;
        if (string.IsNullOrEmpty(dn)) return;
        await JS.InvokeVoidAsync("sigilCopyText", dn);
        ToastService.ShowSuccess("Subject DN copied to clipboard");
    }

    private async Task DownloadCrlAsync()
    {
        if (contextMenuNode?.EntityType != "Crl") return;
        await JS.InvokeVoidAsync("open", $"/api/crl/{contextMenuNode.Id}/download", "_blank");
    }

    private async Task RepublishCrlAsync()
    {
        if (selectedCrl == null) return;
        try
        {
            await CrlGenService.PublishCrlAsync(selectedCrl.CaCertificateId);
            ToastService.ShowSuccess($"Re-published CRL #{selectedCrl.CrlNumber} to configured CDP URLs.");
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Re-publish failed: {ex.Message}");
        }
    }

    private async Task RevalidateSelectedAsync()
    {
        if (selectedNode == null || selectedNode.EntityType == "Crl") return;

        isRevalidating = true;
        StateHasChanged();

        try
        {
            // Full validation with online CRL resolution
            if (selectedNode.EntityType == "CaCertificate")
                chainValidation = await ChainValidator.ValidateCaCertificateAsync(selectedNode.Id);
            else
                chainValidation = await ChainValidator.ValidateIssuedCertificateAsync(selectedNode.Id);

            if (!string.IsNullOrEmpty(selectedNode.Thumbprint) && chainValidation != null)
            {
                trustDomainValidations[selectedNode.Thumbprint] = chainValidation;
                selectedNode.Status = CertificateManagementService.DeriveStatus(
                    selectedNode.Thumbprint, selectedNode.NotAfter, false, trustDomainValidations);
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Validation failed: {ex.Message}");
        }
        finally
        {
            isRevalidating = false;
            StateHasChanged();
        }
    }

    private async Task GenerateCrlForSelectedAsync()
    {
        if (isGeneratingCrl || selectedNode == null) return;
        if (selectedNode.CertificateRole is not ("RootCA" or "IntermediateCA")) return;

        isGeneratingCrl = true;
        StateHasChanged();

        try
        {
            var result = await CrlGenService.GenerateCrlAsync(selectedNode.Id);
            if (result.IsSuccess)
            {
                ToastService.ShowSuccess($"CRL #{result.CrlNumber} generated ({result.RevokedCount} revoked certs)");
                await LoadTrustDomainTreeAsync(TrustDomainId);
            }
            else
            {
                ToastService.ShowCopyableError($"CRL generation failed: {result.Error}");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"CRL generation failed: {ex.Message}");
        }
        finally
        {
            isGeneratingCrl = false;
            StateHasChanged();
        }
    }

    private async Task ShowPublishCrlDialog()
    {
        if (selectedNode == null) return;

        await using var db = await DbFactory.CreateDbContextAsync();
        var ca = await db.CaCertificates.FindAsync(selectedNode.Id);
        var trustDomain = ca != null ? await db.TrustDomains.FindAsync(ca.TrustDomainId) : null;
        var days = trustDomain?.CrlValidityDays ?? 0;
        if (days <= 0) days = 7;

        crlOverrideNextUpdate = DateTime.UtcNow.AddDays(days);
        crlOverrideDialogHidden = false;
    }

    private async Task GenerateCrlWithOverrideAsync()
    {
        if (selectedNode == null || crlOverrideNextUpdate == null) return;

        crlOverrideDialogHidden = true;
        var validity = crlOverrideNextUpdate.Value - DateTime.UtcNow;
        if (validity <= TimeSpan.Zero)
        {
            ToastService.ShowCopyableError("NextUpdate must be in the future.");
            return;
        }

        isGeneratingCrl = true;
        StateHasChanged();

        try
        {
            var result = await CrlGenService.GenerateCrlAsync(selectedNode.Id, validity);
            if (result.IsSuccess)
            {
                ToastService.ShowSuccess($"CRL #{result.CrlNumber} generated (next update: {result.NextUpdate:yyyy-MM-dd HH:mm} UTC)");
                await LoadTrustDomainTreeAsync(TrustDomainId);
            }
            else
            {
                ToastService.ShowCopyableError($"CRL generation failed: {result.Error}");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"CRL generation failed: {ex.Message}");
        }
        finally
        {
            isGeneratingCrl = false;
            StateHasChanged();
        }
    }

    private async Task PublishAiaForSelectedAsync()
    {
        if (isPublishingAia || selectedNode == null) return;
        if (selectedNode.CertificateRole is not ("RootCA" or "IntermediateCA")) return;

        isPublishingAia = true;
        StateHasChanged();

        try
        {
            var result = await PublishingService.PublishAiaCertificateAsync(selectedNode.Id);
            if (result.Success)
                ToastService.ShowSuccess($"Published certificate to {result.PublishedCount} endpoint(s)");
            else if (result.Error?.Contains("publishing paths") == true)
                ToastService.ShowWarning(result.Error);
            else
                ToastService.ShowCopyableError(result.Error ?? "AIA publish failed.");
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"AIA publish failed: {ex.Message}");
        }
        finally
        {
            isPublishingAia = false;
            StateHasChanged();
        }
    }

    private async Task EnsureIssuerPublishedAsync(int issuingCaId)
    {
        try
        {
            await PublishingService.EnsureIssuerPublishedAsync(issuingCaId);
        }
        catch
        {
        }
    }

    private async Task ValidateOnlineAsync()
    {
        if (selectedNode == null || selectedNode.EntityType == "Crl") return;

        isValidatingOnline = true;
        StateHasChanged();

        try
        {
            if (selectedNode.EntityType == "CaCertificate")
                chainValidation = await ChainValidator.ValidateCaCertificateOnlineAsync(selectedNode.Id);
            else
                chainValidation = await ChainValidator.ValidateIssuedCertificateOnlineAsync(selectedNode.Id);

            if (!string.IsNullOrEmpty(selectedNode.Thumbprint) && chainValidation != null)
            {
                trustDomainValidations[selectedNode.Thumbprint] = chainValidation;
                selectedNode.Status = CertificateManagementService.DeriveStatus(
                    selectedNode.Thumbprint, selectedNode.NotAfter, false, trustDomainValidations);
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Online validation failed: {ex.Message}");
        }
        finally
        {
            isValidatingOnline = false;
            StateHasChanged();
        }
    }

    // --- Rename Methods ---

    private void StartRename()
    {
        if (selectedNode == null) return;
        renamingValue = selectedNode.Name;
        isRenaming = true;
    }

    private void CancelRename()
    {
        isRenaming = false;
    }

    private async Task OnRenameKeyDown(Microsoft.AspNetCore.Components.Web.KeyboardEventArgs e)
    {
        if (e.Key == "Enter") await SaveRenameAsync();
        else if (e.Key == "Escape") CancelRename();
    }

    private async Task SaveRenameAsync()
    {
        if (selectedNode == null || string.IsNullOrWhiteSpace(renamingValue)) return;

        var trimmed = renamingValue.Trim();
        if (trimmed == selectedNode.Name)
        {
            isRenaming = false;
            return;
        }

        var result = await ManagementService.RenameAsync(selectedNode.Id, selectedNode.EntityType, trimmed);
        if (result.Success)
            selectedNode.Name = trimmed;

        isRenaming = false;
        StateHasChanged();
    }

    private string GetCerDownloadUrl()
    {
        if (selectedNode == null) return "#";
        return selectedNode.EntityType == "CaCertificate"
            ? $"/api/ca/{selectedNode.Id}/download/cer"
            : $"/api/issued/{selectedNode.Id}/download/cer";
    }

    private string GetPfxDownloadUrl()
    {
        if (selectedNode == null) return "#";
        return selectedNode.EntityType == "CaCertificate"
            ? $"/api/ca/{selectedNode.Id}/download/p12"
            : $"/api/issued/{selectedNode.Id}/download/p12";
    }

    private async Task CopyPrivateKeyAsync()
    {
        if (selectedNode == null) return;

        var result = await ExportService.ExportPrivateKeyPemAsync(
            selectedNode.Id, selectedNode.EntityType);

        if (!result.Success)
        {
            ToastService.ShowError(result.Error ?? "Failed to export private key.");
            return;
        }

        await JS.InvokeVoidAsync("sigilCopyText", result.Pem);
        ToastService.ShowSuccess("Private key copied to clipboard (PKCS#8 PEM)");
    }

    private async Task CopyCertBase64Async()
    {
        if (selectedNode == null) return;

        var result = await ExportService.ExportCertificateDerBase64Async(
            selectedNode.Id, selectedNode.EntityType);

        if (!result.Success)
        {
            ToastService.ShowError(result.Error ?? "Failed to export certificate.");
            return;
        }

        await JS.InvokeVoidAsync("sigilCopyText", result.Pem);
        ToastService.ShowSuccess("Certificate base64 (DER) copied to clipboard");
    }

    private static string NodeColor(CertificateStatus status) => status switch
    {
        CertificateStatus.Expired => "#e94560",
        CertificateStatus.Revoked => "#9c27b0",
        CertificateStatus.Untrusted => "#d32f2f",
        CertificateStatus.Expiring => "#ff9800",
        CertificateStatus.Stale => "#2196f3",
        _ => ""
    };

    private static bool IsError(CertificateStatus status) =>
        status is CertificateStatus.Expired or CertificateStatus.Revoked or CertificateStatus.Untrusted or CertificateStatus.Stale;

    private string GetPublicKeyInfo()
    {
        if (selectedCert == null) return "Unknown";
        var rsa = selectedCert.GetRSAPublicKey();
        if (rsa != null) return $"RSA {rsa.KeySize}-bit";
        var ecdsa = selectedCert.GetECDsaPublicKey();
        if (ecdsa != null) return $"ECDSA {ecdsa.KeySize}-bit";
        return "Unknown";
    }

    // --- Drag & drop import ---

    private async Task OnFilesCompleted(IEnumerable<FluentInputFileEventArgs> files)
    {
        importError = null;
        importErrors.Clear();

        var fileList = files.Where(f => f.LocalFile != null && !string.IsNullOrEmpty(f.Name)).ToList();

        if (fileList.Count == 0) return;

        // Single file — use the interactive confirm dialog flow
        if (fileList.Count == 1)
        {
            var args = fileList[0];
            try
            {
                var fileBytes = await File.ReadAllBytesAsync(args.LocalFile!.FullName);
                await ProcessUploadedFile(fileBytes, args.Name);
            }
            catch (Exception ex)
            {
                importError = $"Failed to read '{args.Name}': {ex.Message}";
            }
            return;
        }

        // Multiple files — batch import without individual confirm dialogs
        await BatchImportFiles(fileList.Select(f => (f.LocalFile!.FullName, f.Name)).ToList());
    }

    private async Task OnFolderSelected(InputFileChangeEventArgs e)
    {
        importError = null;
        importErrors.Clear();

        var validExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".pfx", ".p12", ".cer", ".crt", ".pem", ".der", ".crl" };

        var filesToProcess = new List<(string TempPath, string FileName)>();

        foreach (var file in e.GetMultipleFiles(500))
        {
            var ext = Path.GetExtension(file.Name).ToLowerInvariant();
            if (!validExtensions.Contains(ext)) continue;

            // Save browser file to temp
            var tempPath = Path.GetTempFileName();
            try
            {
                await using var stream = file.OpenReadStream(10 * 1024 * 1024);
                await using var fs = File.Create(tempPath);
                await stream.CopyToAsync(fs);
                filesToProcess.Add((tempPath, file.Name));
            }
            catch (Exception ex)
            {
                importErrors.Add($"Failed to read '{file.Name}': {ex.Message}");
            }
        }

        if (filesToProcess.Count > 0)
        {
            await BatchImportFiles(filesToProcess);

            // Cleanup temp files
            foreach (var (tempPath, _) in filesToProcess)
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    private async Task BatchImportFiles(List<(string FilePath, string FileName)> files)
    {
        isImportingBatch = true;
        importTotal = files.Count;
        importProgress = 0;
        int successCount = 0;

        // Read all files and detect roles so we can sort CAs before end-entity certs
        var fileEntries = new List<(byte[] Bytes, string FileName, int SortOrder)>();
        foreach (var (filePath, fileName) in files)
        {
            try
            {
                var fileBytes = await File.ReadAllBytesAsync(filePath);
                var ext = Path.GetExtension(fileName).ToLowerInvariant();

                int sortOrder;
                if (ext == ".crl")
                {
                    sortOrder = 3; // CRLs last
                }
                else
                {
                    // Quick-parse to detect role for sorting
                    var parsed = ext is ".pfx" or ".p12"
                        ? (ParsingService.Parse(fileBytes, fileName, "") ?? ParsingService.Parse(fileBytes, fileName, "udap-test"))
                        : ParsingService.Parse(fileBytes, fileName);

                    if (parsed?.DetectedRole == DetectedCertRole.RootCa)
                        sortOrder = 0; // Roots first
                    else if (parsed?.DetectedRole == DetectedCertRole.IntermediateCa)
                        sortOrder = 1; // Then intermediates
                    else
                        sortOrder = 2; // End-entity certs after CAs
                    parsed?.Certificate.Dispose();
                }

                fileEntries.Add((fileBytes, fileName, sortOrder));
            }
            catch (Exception ex)
            {
                importErrors.Add($"Failed to read '{fileName}': {ex.Message}");
            }
        }

        var sorted = fileEntries.OrderBy(f => f.SortOrder).ToList();
        importTotal = sorted.Count;

        // First pass
        var retryList = new List<(byte[] Bytes, string FileName)>();
        foreach (var (fileBytes, fileName, _) in sorted)
        {
            importProgress++;
            StateHasChanged();

            try
            {
                var ext = Path.GetExtension(fileName).ToLowerInvariant();

                if (ext == ".crl")
                {
                    var result = await CrlImporter.ImportCrlAsync(fileBytes, fileName, TrustDomainId);
                    if (result.IsSuccess)
                        successCount++;
                    else
                        importErrors.Add($"{fileName}: {result.Error}");
                }
                else
                {
                    var errorCountBefore = importErrors.Count;
                    var imported = await TryAutoImportCert(fileBytes, fileName);
                    if (imported)
                        successCount++;
                    else if (importErrors.Count > errorCountBefore)
                        retryList.Add((fileBytes, fileName)); // Had an error (not just queued for password)
                }
            }
            catch (Exception ex)
            {
                importErrors.Add($"{fileName}: {ex.Message}");
            }
        }

        // Second pass: retry files that failed (CAs should now exist)
        if (retryList.Count > 0)
        {
            // Clear errors from first pass for files we're retrying
            var retryNames = retryList.Select(r => r.FileName).ToHashSet();
            importErrors.RemoveAll(e => retryNames.Any(n => e.StartsWith($"{n}:")));

            foreach (var (fileBytes, fileName) in retryList)
            {
                try
                {
                    var imported = await TryAutoImportCert(fileBytes, fileName);
                    if (imported)
                        successCount++;
                }
                catch (Exception ex)
                {
                    importErrors.Add($"{fileName}: {ex.Message}");
                }
            }
        }

        isImportingBatch = false;

        if (successCount > 0)
        {
            ToastService.ShowCopyableSuccess($"Imported {successCount} of {files.Count} files.");
            await LoadTrustDomainTreeAsync(TrustDomainId);
        }

        if (importErrors.Count > 0 && successCount == 0
            && pendingPasswordQueue.Count == 0 && pendingCaSelectQueue.Count == 0)
        {
            importError = "No files were imported successfully.";
        }

        // Process queued PFX files that need manual password entry, then unmatched certs
        if (pendingPasswordQueue.Count > 0)
            ProcessNextPendingPassword();
        else if (pendingCaSelectQueue.Count > 0)
            ProcessNextPendingCaSelect();
    }

    private async Task<bool> TryAutoImportCert(byte[] fileBytes, string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        ParsedCertificate? parsed = null;
        string? usedPassword = null;

        if (ext is ".pfx" or ".p12")
        {
            parsed = ParsingService.Parse(fileBytes, fileName, "");
            if (parsed != null) usedPassword = "";

            if (parsed == null)
            {
                parsed = ParsingService.Parse(fileBytes, fileName, "udap-test");
                if (parsed != null) usedPassword = "udap-test";
            }

            if (parsed == null)
            {
                pendingPasswordQueue.Enqueue((fileBytes, fileName));
                return false;
            }
        }
        else
        {
            parsed = ParsingService.Parse(fileBytes, fileName);
            if (parsed == null)
            {
                importErrors.Add($"{fileName}: Could not parse certificate");
                return false;
            }
        }

        try
        {
            var result = await ImportService.ImportParsedCertificateAsync(
                parsed, TrustDomainId, password: usedPassword, rawFileOverride: fileBytes);
            parsed.Certificate.Dispose();

            if (result.NeedsCaSelection)
            {
                pendingCaSelectQueue.Enqueue((fileBytes, fileName, usedPassword));
                return false;
            }

            return result.Success;
        }
        catch (Exception ex)
        {
            importErrors.Add($"{fileName}: {ex.Message}");
            parsed.Certificate.Dispose();
            return false;
        }
    }

    private async Task TriggerFolderUpload()
    {
        await JS.InvokeVoidAsync("sigilFolderUpload", "folder-input");
    }

    // --- Auto Renew ---

    private async Task ToggleAutoRenewAsync(bool enabled)
    {
        if (selectedNode == null) return;

        await ManagementService.SetAutoRenewAsync(selectedNode.Id, selectedNode.EntityType, enabled);
        selectedNodeAutoRenew = enabled;
    }

    // --- Delete & Move ---

    private async Task ArchiveSelectedAsync()
    {
        if (selectedNode == null) return;

        var dialog = await DialogService.ShowConfirmationAsync(
            $"Archive '{selectedNode.Name}'? It will be hidden from the tree but preserved in the database.",
            "Archive", "Cancel", "Confirm Archive");
        var result = await dialog.Result;

        if (result.Cancelled) return;

        var archiveResult = await ManagementService.ArchiveAsync(selectedNode.Id, selectedNode.EntityType);
        if (archiveResult.Success)
            ToastService.ShowCopyableSuccess($"Archived '{selectedNode.Name}'");
        else
            ToastService.ShowCopyableError(archiveResult.Error ?? "Archive failed.");

        await ClearSelectionAndReloadTreeAsync();
    }

    private async Task DeleteSelectedAsync()
    {
        if (selectedNode == null) return;

        var impacts = selectedNode.EntityType switch
        {
            "CaCertificate" => await ManagementService.GetCaDeletionImpactAsync(selectedNode.Id),
            "IssuedCertificate" => await ManagementService.GetIssuedDeletionImpactAsync(selectedNode.Id),
            _ => new List<ImpactItem>()
        };

        ShowImpactDialog(
            title: $"Delete '{selectedNode.Name}'?",
            message: "This cannot be undone.",
            confirmLabel: "Delete Forever",
            impacts: impacts,
            onConfirm: ConfirmDeleteSelectedAsync);
    }

    private async Task ConfirmDeleteSelectedAsync()
    {
        if (selectedNode == null) return;

        var deleteResult = await ManagementService.DeleteAsync(
            selectedNode.Id, selectedNode.EntityType, DeleteRemoteKeyAsync);

        if (deleteResult.Success)
        {
            ToastService.ShowCopyableSuccess($"Permanently deleted '{selectedNode.Name}'");
            await ClearSelectionAndReloadTreeAsync();
        }
        else
        {
            ToastService.ShowCopyableError(deleteResult.Error ?? "Delete failed.");
        }
    }

    private void ShowImpactDialog(string title, string message, string confirmLabel,
        List<ImpactItem> impacts, Func<Task> onConfirm)
    {
        impactDialogTitle = title;
        impactDialogMessage = message;
        impactDialogConfirmLabel = confirmLabel;
        impactDialogImpacts = impacts;
        impactDialogOnConfirm = onConfirm;
        impactDialogBusy = false;
        impactDialogHidden = false;
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

    private void OnImpactDialogCancel()
    {
        impactDialogHidden = true;
    }

    /// <summary>
    /// Deletes a remote signing key (Vault Transit or GCP KMS) if the StoreProviderHint indicates one.
    /// </summary>
    private async Task DeleteRemoteKeyAsync(string? storeProviderHint)
    {
        if (string.IsNullOrEmpty(storeProviderHint))
            return;

        try
        {
            if (storeProviderHint.StartsWith("vault-transit:"))
            {
                var keyName = storeProviderHint["vault-transit:".Length..];
                if (!string.IsNullOrEmpty(keyName))
                    await VaultTransitProvider.DeleteKeyAsync(keyName);
            }
            else if (storeProviderHint.StartsWith("gcp-kms:"))
            {
                var keyId = storeProviderHint["gcp-kms:".Length..];
                if (!string.IsNullOrEmpty(keyId))
                    await GcpKmsProvider.DestroyKeyVersionAsync(keyId);
            }
        }
        catch (Exception ex)
        {
            // Log but don't block the DB delete — the remote key is orphaned but that's better
            // than leaving the DB record pointing to a deleted cert
            ToastService.ShowCopyableError($"Remote key cleanup failed: {ex.Message}");
        }
    }

    private async Task ClearSelectionAndReloadTreeAsync()
    {
        selectedTreeItem = null;
        selectedNode = null;
        selectedCert?.Dispose();
        selectedCert = null;
        selectedCrl = null;
        chainValidation = null;
        asn1Root = null;
        CloseIssuerDetails();

        await LoadTrustDomainTreeAsync(TrustDomainId);
    }

    private void ShowMoveDialog()
    {
        moveTargetTrustDomain = null;
        moveDialogHidden = false;
    }

    private async Task MoveSelectedAsync()
    {
        if (selectedNode == null || moveTargetTrustDomain == null) return;

        var moveResult = await ManagementService.MoveAsync(
            selectedNode.Id, selectedNode.EntityType, moveTargetTrustDomain.Id);

        moveDialogHidden = true;

        if (moveResult.Success)
        {
            ToastService.ShowCopyableSuccess($"Moved '{selectedNode.Name}' to '{moveTargetTrustDomain.Name}'");
            selectedNode = null;
            selectedCert?.Dispose();
            selectedCert = null;
            chainValidation = null;
            await LoadTrustDomainTreeAsync(TrustDomainId);
        }
        else
        {
            ToastService.ShowCopyableError(moveResult.Error ?? "Move failed.");
        }
    }

    private async Task ProcessUploadedFile(byte[] fileBytes, string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();

        if (ext == ".crl")
        {
            await ImportCrlAsync(fileBytes, fileName);
            return;
        }

        if (ext is ".pfx" or ".p12")
        {
            // Try with empty password first
            var parsed = ParsingService.Parse(fileBytes, fileName, "");
            if (parsed == null)
            {
                // Try common default
                parsed = ParsingService.Parse(fileBytes, fileName, "udap-test");
            }

            if (parsed != null)
            {
                await ShowConfirmDialogAsync(parsed);
            }
            else
            {
                // Need password
                pendingFileBytes = fileBytes;
                pendingFileName = fileName;
                pfxPassword = string.Empty;
                passwordError = null;
                passwordDialogHidden = false;
            }
        }
        else
        {
            var parsed = ParsingService.Parse(fileBytes, fileName);
            if (parsed != null)
            {
                await ShowConfirmDialogAsync(parsed);
            }
            else
            {
                importError = $"Could not parse certificate from '{fileName}'. Ensure it is a valid certificate file.";
            }
        }
    }

    private void ProcessNextPendingPassword()
    {
        if (pendingPasswordQueue.Count == 0)
        {
            // Password queue done — process any unmatched certs
            if (pendingCaSelectQueue.Count > 0)
                ProcessNextPendingCaSelect();
            return;
        }

        var (bytes, name) = pendingPasswordQueue.Dequeue();
        pendingFileBytes = bytes;
        pendingFileName = name;
        pfxPassword = string.Empty;
        passwordError = null;
        passwordDialogHidden = false;
    }

    private async Task ImportWithPasswordAsync()
    {
        if (pendingFileBytes == null) return;

        passwordError = null;
        var parsed = ParsingService.Parse(pendingFileBytes, pendingFileName, pfxPassword);
        if (parsed != null)
        {
            passwordDialogHidden = true;
            passwordError = null;
            pendingFileBytes = null;

            // In batch mode (queue has items or came from batch), auto-import
            if (pendingPasswordQueue.Count > 0)
            {
                await TryAutoImportCertWithParsed(parsed, pendingFileName, pfxPassword);
                await LoadTrustDomainTreeAsync(TrustDomainId);
                ProcessNextPendingPassword();
            }
            else
            {
                await ShowConfirmDialogAsync(parsed);
            }
        }
        else
        {
            // Keep dialog open — let user retry with a different password
            passwordError = "Incorrect password. Try again.";
            pfxPassword = string.Empty;
        }
    }

    private async Task SkipPasswordFile()
    {
        passwordDialogHidden = true;
        passwordError = null;
        importErrors.Add($"{pendingFileName}: Skipped (no password provided)");
        pendingFileBytes = null;
        ProcessNextPendingPassword();
    }

    private void CancelPasswordDialog()
    {
        passwordDialogHidden = true;
        passwordError = null;
        pendingFileBytes = null;
        pendingPasswordQueue.Clear();
    }

    private async Task TryAutoImportCertWithParsed(ParsedCertificate parsed, string fileName, string password)
    {
        try
        {
            var result = await ImportService.ImportParsedCertificateAsync(
                parsed, TrustDomainId, password: password);

            if (result.NeedsCaSelection)
            {
                pendingCaSelectQueue.Enqueue((parsed.RawFileBytes ?? Array.Empty<byte>(), fileName, password));
                parsed.Certificate.Dispose();
                return;
            }

            parsed.Certificate.Dispose();
            ToastService.ShowCopyableSuccess($"Imported '{fileName}'");
        }
        catch (Exception ex)
        {
            importErrors.Add($"{fileName}: {ex.Message}");
            parsed.Certificate.Dispose();
        }
    }

    private async Task ShowConfirmDialogAsync(ParsedCertificate parsed)
    {
        parsedCert = parsed;
        importName = Path.GetFileNameWithoutExtension(parsed.FileName);
        matchedParentCaId = null;
        chainMatchDescription = null;

        // Try to find where this cert fits in the existing chain
        if (parsed.DetectedRole != DetectedCertRole.RootCa && parsed.AuthorityKeyIdentifier != null)
        {
            await using var db = await DbFactory.CreateDbContextAsync();

            var matchingCa = await db.CaCertificates
                .Where(ca => ca.TrustDomainId == TrustDomainId)
                .ToListAsync();

            foreach (var ca in matchingCa)
            {
                // Load the CA cert to get its SKI
                try
                {
                    var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                    var skiExt = caCert.Extensions["2.5.29.14"];
                    if (skiExt != null)
                    {
                        var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
                        if (ski.SubjectKeyIdentifier == parsed.AuthorityKeyIdentifier)
                        {
                            matchedParentCaId = ca.Id;
                            chainMatchDescription = $"Issued by: {ca.Name} ({ca.Subject})";
                            break;
                        }
                    }
                    caCert.Dispose();
                }
                catch { }
            }

            if (matchedParentCaId == null)
            {
                chainMatchDescription = "No matching issuer found in this trustDomain. Will be added as a root.";
            }
        }

        confirmDialogHidden = false;
        StateHasChanged();
    }

    private async Task ConfirmImportAsync()
    {
        if (parsedCert == null || string.IsNullOrWhiteSpace(importName)) return;

        try
        {
            var result = await ImportService.ImportParsedCertificateAsync(
                parsedCert, TrustDomainId,
                name: importName,
                password: pfxPassword,
                issuingCaId: matchedParentCaId);

            if (result.NeedsCaSelection)
            {
                confirmDialogHidden = true;
                pendingCaSelectParsed = parsedCert;
                parsedCert = null;
                await ShowCaSelectDialog(
                    pendingCaSelectParsed.RawFileBytes,
                    pendingCaSelectParsed.FileName,
                    pendingCaSelectParsed.HasPrivateKey ? pfxPassword : null);
                return;
            }

            confirmDialogHidden = true;
            showDropZone = false;
            importError = null;
            parsedCert?.Certificate.Dispose();
            parsedCert = null;

            if (result.Success)
            {
                ToastService.ShowCopyableSuccess($"Certificate '{importName}' imported successfully.");
                await LoadTrustDomainTreeAsync(TrustDomainId);
            }
            else
            {
                importError = result.Error ?? "Import failed.";
            }
        }
        catch (Exception ex)
        {
            importError = $"Import failed: {ex.Message}";
            confirmDialogHidden = true;
        }
    }

    private async Task ImportCrlAsync(byte[] crlBytes, string fileName)
    {
        var result = await CrlImporter.ImportCrlAsync(crlBytes, fileName, TrustDomainId);

        if (!result.IsSuccess)
        {
            importError = result.Error;
            return;
        }

        showDropZone = false;
        var sigStatus = result.SignatureValid ? "signature valid" : "signature INVALID";
        var nextUpdateStr = result.NextUpdate.HasValue ? TimeDisplay.FormatShort(result.NextUpdate.Value) : "unknown";
        ToastService.ShowCopyableSuccess(
            $"CRL #{result.CrlNumber} imported ({sigStatus}): {result.RevokedCount} revocation(s), next update {nextUpdateStr}");
    }

    private void CancelConfirmDialog()
    {
        confirmDialogHidden = true;
        parsedCert?.Certificate.Dispose();
        parsedCert = null;
    }

    private static string GetRoleBadgeColor(DetectedCertRole role) => role switch
    {
        DetectedCertRole.RootCa => "#2d6a4f",
        DetectedCertRole.IntermediateCa => "#1976d2",
        DetectedCertRole.EndEntity => "#666",
        _ => "#666"
    };

    // --- CA selection for unmatched certs ---

    private async Task LoadAvailableCasAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();
        availableCas = await db.CaCertificates
            .Where(ca => ca.TrustDomainId == TrustDomainId)
            .OrderBy(ca => ca.ParentId == null ? 0 : 1) // Roots first
            .ThenBy(ca => ca.Name)
            .Select(ca => new CaSelectOption
            {
                Id = ca.Id,
                Name = ca.Name,
                Subject = ca.Subject,
                IsRoot = ca.ParentId == null
            })
            .ToListAsync();
    }

    private async Task ShowCaSelectDialog(byte[] fileBytes, string fileName, string? password)
    {
        await LoadAvailableCasAsync();

        if (availableCas.Count == 0)
        {
            importErrors.Add($"{fileName}: No CAs exist in this trustDomain to assign under");
            return;
        }

        pendingFileBytes = fileBytes;
        pendingFileName = fileName;
        pfxPassword = password ?? string.Empty;
        selectedCaForAssignment = null;
        caSelectDialogHidden = false;
        StateHasChanged();
    }

    private async void ProcessNextPendingCaSelect()
    {
        if (pendingCaSelectQueue.Count == 0) return;

        var (bytes, name, password) = pendingCaSelectQueue.Dequeue();
        pendingCaSelectParsed = null; // Batch items need re-parse
        await ShowCaSelectDialog(bytes, name, password);
    }

    private async Task ConfirmCaAssignmentAsync()
    {
        if (selectedCaForAssignment == null) return;

        // Use pre-parsed cert if available, otherwise re-parse from bytes
        var parsed = pendingCaSelectParsed;
        if (parsed == null && pendingFileBytes != null)
        {
            var ext = Path.GetExtension(pendingFileName).ToLowerInvariant();
            parsed = ext is ".pfx" or ".p12"
                ? ParsingService.Parse(pendingFileBytes, pendingFileName, pfxPassword)
                : ParsingService.Parse(pendingFileBytes, pendingFileName);
        }

        if (parsed == null)
        {
            ToastService.ShowCopyableError($"Could not parse '{pendingFileName}'");
            caSelectDialogHidden = true;
            pendingCaSelectParsed = null;
            ProcessNextPendingCaSelect();
            return;
        }

        try
        {
            await SaveWithCaAssignmentAsync(parsed);
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Import failed: {ex.Message}");
            parsed.Certificate.Dispose();
        }
        pendingCaSelectParsed = null;

        caSelectDialogHidden = true;
        pendingFileBytes = null;

        if (pendingCaSelectQueue.Count > 0)
        {
            ProcessNextPendingCaSelect();
        }
        else
        {
            await LoadTrustDomainTreeAsync(TrustDomainId);
        }
    }

    private async Task SaveWithCaAssignmentAsync(ParsedCertificate parsed)
    {
        var result = await ImportService.ImportParsedCertificateAsync(
            parsed, TrustDomainId,
            name: Path.GetFileNameWithoutExtension(pendingFileName),
            password: pfxPassword,
            issuingCaId: selectedCaForAssignment!.Id,
            rawFileOverride: pendingFileBytes);

        parsed.Certificate.Dispose();

        if (result.Success)
        {
            var label = result.AlreadyExists ? "Merged PFX into existing" : "assigned under";
            ToastService.ShowCopyableSuccess(
                $"'{result.ImportedName}' {label} '{selectedCaForAssignment!.Name}'");
        }
        else
        {
            ToastService.ShowCopyableError(result.Error ?? "Import failed.");
        }
    }

    private void SkipCaAssignment()
    {
        caSelectDialogHidden = true;
        importErrors.Add($"{pendingFileName}: Skipped (no CA selected)");
        pendingFileBytes = null;
        ProcessNextPendingCaSelect();
    }

    private void CancelCaAssignment()
    {
        caSelectDialogHidden = true;
        pendingFileBytes = null;
        pendingCaSelectQueue.Clear();
    }

    // Issuer detail state
    private X509Certificate2? issuerCert;
    private CertificateChainNodeViewModel? issuerNode;
    private Asn1Node? issuerAsn1Root;

    // Issuance constants
    private static readonly SanType[] sanTypeOptions = Enum.GetValues<SanType>();

    private static string GetSanPlaceholder(SanType type) => type switch
    {
        SanType.Uri => "https://example.com/fhir/r4",
        SanType.Dns => "example.com",
        SanType.Email => "admin@example.com",
        SanType.IpAddress => "192.168.1.1",
        _ => ""
    };

    // --- Issuer Navigation Methods ---

    private async Task UpdateTreeHighlightsAsync()
    {
        try
        {
            var selectedId = selectedNode != null ? $"tree-{selectedNode.Thumbprint}" : null;
            var issuerId = issuerNode != null ? $"tree-{issuerNode.Thumbprint}" : null;
            await JS.InvokeVoidAsync("sigilHighlightTree", selectedId, issuerId);
        }
        catch { /* JS not ready yet */ }
    }

    private string GetTreeItemCrlStyle(CertificateChainNodeViewModel node)
    {
        if (IsError(node.Status))
            return $"color: {NodeColor(node.Status)};";
        return "font-style: italic; opacity: 0.8;";
    }

    private async Task LoadIssuerDetailsAsync()
    {
        if (selectedCert == null) return;
        await LoadIssuerByCert(selectedCert);
    }

    private async Task LoadIssuerOfIssuerDetailsAsync()
    {
        if (issuerCert == null || issuerCert.Subject == issuerCert.Issuer) return;

        // The current issuer becomes the selected cert, and we load its issuer
        var prevIssuer = issuerCert;

        // Find the node for the current issuer and make it the primary selection
        var issuerThumbprint = issuerCert.Thumbprint;
        var node = FindNodeByThumbprint(treeNodes, issuerThumbprint);
        if (node != null)
        {
            await SelectNode(node);
        }

        // Now load the issuer of that cert
        await LoadIssuerByCert(selectedCert!);
    }

    private async Task LoadIssuerByCert(X509Certificate2 cert)
    {
        CloseIssuerDetails();

        if (cert.Subject == cert.Issuer) return; // self-signed, no parent

        // Find issuer by AKI → SKI match, or by DN match
        await using var db = await DbFactory.CreateDbContextAsync();

        var akiValue = GetAkiKeyId(cert);
        CaCertificate? issuerEntity = null;

        if (akiValue != null)
        {
            // Find CA whose SKI matches our AKI
            var cas = await db.CaCertificates
                .Where(ca => ca.TrustDomainId == TrustDomainId)
                .ToListAsync();

            foreach (var ca in cas)
            {
                try
                {
                    using var caCert = X509Certificate2.CreateFromPem(ca.X509CertificatePem);
                    var ski = caCert.Extensions["2.5.29.14"];
                    if (ski != null)
                    {
                        var skiHex = Convert.ToHexString(ski.RawData.AsSpan(2));
                        if (string.Equals(skiHex, akiValue, StringComparison.OrdinalIgnoreCase))
                        {
                            issuerEntity = ca;
                            break;
                        }
                    }
                }
                catch { }
            }
        }

        if (issuerEntity == null)
        {
            // Fallback: match by issuer DN
            var cas = await db.CaCertificates
                .Where(ca => ca.TrustDomainId == TrustDomainId && ca.Subject == cert.Issuer)
                .ToListAsync();

            issuerEntity = cas.FirstOrDefault();
        }

        if (issuerEntity == null) return;

        try
        {
            issuerCert = X509Certificate2.CreateFromPem(issuerEntity.X509CertificatePem);
            issuerAsn1Root = Asn1Parser.ParsePem(issuerEntity.X509CertificatePem);
            issuerNode = FindNodeByThumbprint(treeNodes, issuerEntity.Thumbprint);
        }
        catch { }

        StateHasChanged();
        await UpdateTreeHighlightsAsync();
    }

    private void CloseIssuerDetails()
    {
        issuerCert?.Dispose();
        issuerCert = null;
        issuerNode = null;
        issuerAsn1Root = null;
    }

    private async Task CloseIssuerDetailsAsync()
    {
        CloseIssuerDetails();
        await UpdateTreeHighlightsAsync();
    }

    private static string? GetAkiKeyId(X509Certificate2 cert)
    {
        var akiExt = cert.Extensions["2.5.29.35"];
        if (akiExt == null || akiExt.RawData.Length < 6) return null;

        // AKI is a SEQUENCE containing [0] KeyIdentifier (tag 0x80)
        // Simple parse: skip SEQUENCE header, look for tag 0x80
        var data = akiExt.RawData;
        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == 0x80)
            {
                int len = data[i + 1];
                if (i + 2 + len <= data.Length)
                {
                    return Convert.ToHexString(data.AsSpan(i + 2, len));
                }
            }
        }

        return null;
    }

    private static CertificateChainNodeViewModel? FindNodeByThumbprint(
        List<CertificateChainNodeViewModel> nodes, string thumbprint)
    {
        foreach (var node in nodes)
        {
            if (string.Equals(node.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                return node;

            var found = FindNodeByThumbprint(node.Children, thumbprint);
            if (found != null) return found;
        }

        return null;
    }

    private string GetIssuerPublicKeyInfo()
    {
        if (issuerCert == null) return "";
        using var rsa = issuerCert.GetRSAPublicKey();
        if (rsa != null) return $"RSA {rsa.KeySize}-bit";
        using var ecdsa = issuerCert.GetECDsaPublicKey();
        if (ecdsa != null) return $"ECDSA {ecdsa.KeySize}-bit";
        return "Unknown";
    }

    // --- Issuance Methods ---

    private async Task ShowIssuanceDialog(int? issuingCaId, string? issuingCaName)
    {
        isRenewMode = false;
        urlChangeWarnings.Clear();
        issuingCaIdForIssuance = issuingCaId;
        issuingCaNameForIssuance = issuingCaName;
        issuingCaNotAfter = null;

        await using var db = await DbFactory.CreateDbContextAsync();

        // Load issuing CA's NotAfter to clamp validity
        if (issuingCaId.HasValue)
        {
            var ca = await db.CaCertificates.FindAsync(issuingCaId.Value);
            issuingCaNotAfter = ca?.NotAfter;
        }

        var allTemplates = await db.CertificateTemplates
            .Include(t => t.SanLists)
            .OrderBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync();

        if (issuingCaId == null)
        {
            // Self-signed root only
            availableTemplates = allTemplates
                .Where(t => t.CertificateType == CertificateType.RootCa)
                .ToList();
        }
        else
        {
            // Intermediate + end-entity templates
            availableTemplates = allTemplates
                .Where(t => t.CertificateType != CertificateType.RootCa)
                .ToList();
        }

        selectedTemplate = availableTemplates.FirstOrDefault();
        OnTemplateSelected(selectedTemplate);

        issuanceSans.Clear();
        issuanceKeyStorage = "local";
        issuanceCertName = string.Empty;
        issuanceSubjectDn = string.Empty;
        isIssuing = false;

        var cacheKey = PasswordCacheKey(issuingCaId);
        var cached = PasswordCache.Get(cacheKey);
        if (!string.IsNullOrEmpty(cached))
        {
            issuancePfxPassword = cached;
            rememberIssuancePassword = true;
        }
        else
        {
            issuancePfxPassword = string.Empty;
            rememberIssuancePassword = false;
        }

        issuanceDialogHidden = false;
    }

    private static string PasswordCacheKey(int? issuingCaId) =>
        issuingCaId.HasValue ? $"ca-{issuingCaId.Value}" : "root-ca";

    private async Task OpenTrustDomainEditAsync()
    {
        if (TrustDomainId <= 0) return;
        await JS.InvokeVoidAsync("open", $"/trust-domains?edit={TrustDomainId}", "_blank");
    }

    private async Task CheckRemoteKeysAsync(List<CertificateChainNodeViewModel> roots)
    {
        var vaultNodes = new List<CertificateChainNodeViewModel>();
        CollectVaultNodes(roots, vaultNodes);
        if (vaultNodes.Count == 0) return;

        // Probe each key in parallel
        var tasks = vaultNodes.Select(async node =>
        {
            if (string.IsNullOrEmpty(node.KeyIdentifier)) return;
            var exists = await VaultTransitProvider.KeyExistsAsync(node.KeyIdentifier);
            node.RemoteKeyMissing = !exists;
        });

        try
        {
            await Task.WhenAll(tasks);
            treeVersion++;
            await InvokeAsync(StateHasChanged);
        }
        catch
        {
            // Best-effort check — UI shouldn't break if Vault is unreachable
        }
    }

    private static void CollectVaultNodes(List<CertificateChainNodeViewModel> nodes, List<CertificateChainNodeViewModel> sink)
    {
        foreach (var node in nodes)
        {
            if (node.KeyStorage == "vault-transit" && !string.IsNullOrEmpty(node.KeyIdentifier))
                sink.Add(node);
            CollectVaultNodes(node.Children, sink);
        }
    }

    private void OnTemplateSelected(CertificateTemplate? template)
    {
        selectedTemplate = template;
        if (template == null) return;

        issuanceNotBeforeNullable = DateTime.UtcNow;
        var desiredNotAfter = DateTime.UtcNow.AddDays(template.ValidityDays);
        if (issuingCaNotAfter.HasValue && desiredNotAfter > issuingCaNotAfter.Value)
            desiredNotAfter = issuingCaNotAfter.Value;
        issuanceNotAfterNullable = desiredNotAfter;

        var baseUrls = (selectedTrustDomain?.BaseUrls ?? new())
            .Select(bu => bu.Url).ToList();
        var validator = IssuanceService.Validator;
        var newCdpUrls = validator.ExpandCdpTemplates(template, baseUrls, issuingCaNameForIssuance);
        var newAiaUrls = validator.ExpandAiaTemplates(template, baseUrls, issuingCaNameForIssuance);

        urlChangeWarnings.Clear();

        // Detect unsubstituted {BaseUrl} placeholders in any final URL — this catches the
        // case where the trustDomain has no base URLs, an empty base URL string, etc.
        noBaseUrlsWarning = newCdpUrls.Any(u => u.Contains("{BaseUrl}", StringComparison.OrdinalIgnoreCase))
            || newAiaUrls.Any(u => u.Contains("{BaseUrl}", StringComparison.OrdinalIgnoreCase));

        if (isRenewMode && renewalOriginalCdpUrls.Count + renewalOriginalAiaUrls.Count > 0)
        {
            var warnings = validator.CompareTemplateUrls(
                renewalOriginalCdpUrls, renewalOriginalAiaUrls,
                newCdpUrls, newAiaUrls);
            urlChangeWarnings.AddRange(warnings.Select(w => w.Message));
        }

        issuanceCdpUrls = newCdpUrls.Select(u => new IssuanceUrlEntry { Value = u }).ToList();
        issuanceAiaUrls = newAiaUrls.Select(u => new IssuanceUrlEntry { Value = u }).ToList();

        if (isRenewMode)
        {
            issuanceSubjectDn = renewalSubjectDn;
            issuanceSans = renewalSans.Select(s => new IssuanceSanEntry { Type = s.Type, Value = s.Value }).ToList();
        }
        else
        {
            if (string.IsNullOrWhiteSpace(issuanceSubjectDn))
                issuanceSubjectDn = template.SubjectTemplate ?? string.Empty;

            var hasUserSans = issuanceSans.Any(s => !string.IsNullOrWhiteSpace(s.Value));
            if (!hasUserSans)
            {
                issuanceSans.Clear();
                if (!string.IsNullOrWhiteSpace(template.SubjectAltNameTypes))
                {
                    foreach (var sanType in template.SubjectAltNameTypes.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var type = sanType.Trim().ToUpperInvariant() switch
                        {
                            "URI" => SanType.Uri,
                            "DNS" => SanType.Dns,
                            "EMAIL" => SanType.Email,
                            "IP" => SanType.IpAddress,
                            _ => SanType.Uri
                        };
                        issuanceSans.Add(new IssuanceSanEntry { Type = type, Value = string.Empty });
                    }
                }
            }
        }

        templateSanLists = template.SanLists?.Where(s => s != null).ToList() ?? new();
    }

    private async Task EnsureTemplateSanListsLoadedAsync(CertificateTemplate template)
    {
        if (template.SanLists != null && template.SanLists.Count > 0) return;

        await using var db = await DbFactory.CreateDbContextAsync();
        var loaded = await db.CertificateTemplates
            .Include(t => t.SanLists)
            .FirstOrDefaultAsync(t => t.Id == template.Id);

        if (loaded?.SanLists != null)
        {
            template.SanLists = loaded.SanLists;
            templateSanLists = loaded.SanLists.ToList();
        }
    }

    private void ShowSanListPickerDialog(SanList list)
    {
        sanListForPicker = list;
        sanPickerSelectAll = false;
        sanPickerItems.Clear();

        foreach (var part in list.Items.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var colonIdx = part.IndexOf(':');
            if (colonIdx > 0)
            {
                var typeName = part[..colonIdx];
                var value = part[(colonIdx + 1)..];
                var sanType = typeName.ToUpperInvariant() switch
                {
                    "URI" => SanType.Uri,
                    "DNS" => SanType.Dns,
                    "EMAIL" => SanType.Email,
                    "IP" => SanType.IpAddress,
                    _ => SanType.Uri
                };
                var alreadyAdded = issuanceSans.Any(s => s.Type == sanType && s.Value == value);
                sanPickerItems.Add(new SanListPickerItem { Type = sanType, Value = value, Selected = alreadyAdded });
            }
        }

        sanPickerDialogHidden = false;
    }

    private void ToggleSanPickerSelectAll(bool selectAll)
    {
        sanPickerSelectAll = selectAll;
        foreach (var item in sanPickerItems)
            item.Selected = selectAll;
    }

    private void ApplySanListPicker()
    {
        foreach (var item in sanPickerItems)
        {
            var exists = issuanceSans.Any(s => s.Type == item.Type && s.Value == item.Value);
            if (item.Selected && !exists)
                issuanceSans.Add(new IssuanceSanEntry { Type = item.Type, Value = item.Value });
            else if (!item.Selected && exists)
            {
                var match = issuanceSans.First(s => s.Type == item.Type && s.Value == item.Value);
                issuanceSans.Remove(match);
            }
        }

        sanPickerDialogHidden = true;
    }

    private void AddSanEntry()
    {
        issuanceSans.Add(new IssuanceSanEntry { Type = SanType.Uri, Value = string.Empty });
    }

    private void RemoveSanEntry(IssuanceSanEntry entry)
    {
        issuanceSans.Remove(entry);
    }

    private async Task IssueCertificateAsync()
    {
        if (isIssuing) return;
        if (selectedTemplate == null || string.IsNullOrWhiteSpace(issuanceSubjectDn)) return;

        isIssuing = true;
        StateHasChanged();

        try
        {
            var cdpUrls = selectedTemplate.IncludeCdp
                ? issuanceCdpUrls.Where(u => !string.IsNullOrWhiteSpace(u.Value)).Select(u => u.Value).ToList()
                : new List<string>();
            var aiaUrls = selectedTemplate.IncludeAia
                ? issuanceAiaUrls.Where(u => !string.IsNullOrWhiteSpace(u.Value)).Select(u => u.Value).ToList()
                : new List<string>();

            // Ensure the issuing CA's cert and CRL are published before validating URLs
            if (issuingCaIdForIssuance.HasValue)
            {
                await EnsureIssuerPublishedAsync(issuingCaIdForIssuance.Value);
            }

            // Warn about missing CDP/AIA when the template expects them
            var warnings = new List<string>();
            if (selectedTemplate.IncludeCdp && cdpUrls.Count == 0)
                warnings.Add("CRL Distribution Point (CDP) URLs are empty but the template has CDP enabled.");
            if (selectedTemplate.IncludeAia && aiaUrls.Count == 0)
                warnings.Add("Authority Information Access (AIA) URLs are empty but the template has AIA enabled.");

            // Validate that provided CDP and AIA URLs resolve
            var unreachableUrls = await ValidateEndpointUrlsAsync(cdpUrls, aiaUrls);
            foreach (var u in unreachableUrls)
                warnings.Add($"{u.Url}: {u.Error}");

            if (warnings.Count > 0)
            {
                var warningList = string.Join("\n", warnings.Select(w => $"  \u2022 {w}"));
                var dialog = await DialogService.ShowConfirmationAsync(
                    $"The following issue(s) were detected:\n\n{warningList}\n\nCertificates issued without valid CDP/AIA endpoints may cause chain validation failures. Continue anyway?",
                    "Issue Anyway", "Cancel", "Endpoint Warnings");
                var dialogResult = await dialog.Result;
                if (dialogResult.Cancelled)
                {
                    return;
                }
            }

            var request = new CertificateIssuanceRequest
            {
                IssuingCaCertificateId = issuingCaIdForIssuance,
                TemplateId = selectedTemplate.Id,
                TrustDomainId = TrustDomainId,
                SubjectDn = issuanceSubjectDn,
                CertificateName = issuanceCertName,
                SubjectAltNames = issuanceSans
                    .Where(s => !string.IsNullOrWhiteSpace(s.Value))
                    .Select(s => new SanEntry(s.Type, s.Value))
                    .ToList(),
                CdpUrls = cdpUrls,
                AiaUrls = aiaUrls,
                NotBefore = issuanceNotBeforeNullable.HasValue ? new DateTimeOffset(issuanceNotBeforeNullable.Value, TimeSpan.Zero) : null,
                NotAfter = issuanceNotAfterNullable.HasValue ? new DateTimeOffset(issuanceNotAfterNullable.Value, TimeSpan.Zero) : null,
                PfxPassword = issuancePfxPassword,
                SigningProviderOverride = issuanceKeyStorage,
            };

            var result = await IssuanceService.IssueCertificateAsync(request);

            if (result.Success)
            {
                // Generate initial CRL for newly issued CA certificates
                if (result.EntityType == "CaCertificate" && result.EntityId.HasValue)
                {
                    var crlResult = await CrlGenService.GenerateCrlAsync(result.EntityId.Value);
                    if (!crlResult.IsSuccess)
                        ToastService.ShowWarning($"Initial CRL generation failed: {crlResult.Error}");
                }

                // Save or clear PFX password in session cache based on user preference
                if (issuanceKeyStorage == "local")
                {
                    var cacheKey = PasswordCacheKey(issuingCaIdForIssuance);
                    if (rememberIssuancePassword && !string.IsNullOrEmpty(issuancePfxPassword))
                        PasswordCache.Save(cacheKey, issuancePfxPassword);
                    else
                        PasswordCache.Clear(cacheKey);
                }

                issuanceDialogHidden = true;
                ToastService.ShowCopyableSuccess($"Certificate issued: {result.Thumbprint}");
                await LoadTrustDomainTreeAsync(TrustDomainId);
            }
            else
            {
                ToastService.ShowCopyableError(result.Error ?? "Unknown error");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Issuance failed: {ex.Message}");
        }
        finally
        {
            isIssuing = false;
            StateHasChanged();
        }
    }

    private Task<List<(string Url, string Error)>> ValidateEndpointUrlsAsync(List<string> cdpUrls, List<string> aiaUrls)
    {
        // Only validate URL format (must be absolute http/https). Reachability is not checked —
        // these URLs are consumed by clients at runtime, not by Sigil's host, so resolvability
        // from Sigil's network is irrelevant and the HEAD probe just slows things down.
        var invalid = new List<(string Url, string Error)>();
        foreach (var url in cdpUrls.Concat(aiaUrls))
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var absolute) ||
                (absolute.Scheme != Uri.UriSchemeHttp && absolute.Scheme != Uri.UriSchemeHttps))
            {
                invalid.Add((url, "Not an absolute http(s) URL"));
            }
        }
        return Task.FromResult(invalid);
    }

    private async Task ShowSimilarDialog()
    {
        if (selectedNode == null || selectedCert == null) return;

        renewalOriginalCdpUrls = ExtractExtensionUrls(selectedCert, "2.5.29.31");
        renewalOriginalAiaUrls = ExtractExtensionUrls(selectedCert, "1.3.6.1.5.5.7.1.1");
        urlChangeWarnings.Clear();

        renewalSubjectDn = selectedCert.Subject;
        renewalSans.Clear();
        foreach (var san in subjectAltNames)
        {
            var trimmed = san.Trim();
            if (TryParseSan(trimmed, "URL=", SanType.Uri, out var entry) ||
                TryParseSan(trimmed, "URI:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "Uri:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "DNS Name=", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "DNS:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "Dns:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "RFC822 Name=", SanType.Email, out entry) ||
                TryParseSan(trimmed, "email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "Email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "IP Address=", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IP:", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IpAddress:", SanType.IpAddress, out entry))
            {
                renewalSans.Add(entry);
            }
        }

        int? issuingCaId = null;
        string? issuingCaName = null;

        await using var db = await DbFactory.CreateDbContextAsync();

        if (selectedNode.CertificateRole == "EndEntity")
        {
            var issued = await db.IssuedCertificates
                .Include(i => i.IssuingCaCertificate)
                .FirstOrDefaultAsync(i => i.Thumbprint == selectedNode.Thumbprint);
            if (issued != null)
            {
                issuingCaId = issued.IssuingCaCertificateId;
                issuingCaName = issued.IssuingCaCertificate.Name;
            }
        }
        else if (selectedNode.CertificateRole == "IntermediateCA")
        {
            var ca = await db.CaCertificates
                .Include(c => c.Parent)
                .FirstOrDefaultAsync(c => c.Thumbprint == selectedNode.Thumbprint);
            if (ca?.Parent != null)
            {
                issuingCaId = ca.ParentId;
                issuingCaName = ca.Parent.Name;
            }
        }
        else if (selectedNode.CertificateRole == "RootCA")
        {
            issuingCaId = null;
            issuingCaName = null;
        }

        isRenewMode = true;
        await ShowIssuanceDialog(issuingCaId, issuingCaName);
        isRenewMode = true;

        var targetType = selectedNode.CertificateRole switch
        {
            "RootCA" => CertificateType.RootCa,
            "IntermediateCA" => CertificateType.IntermediateCa,
            "EndEntity" => CertificateType.EndEntityClient,
            _ => CertificateType.EndEntityClient
        };

        if (selectedNode.CertificateRole == "EndEntity")
        {
            var issued = await db.IssuedCertificates.FindAsync(selectedNode.Id);
            if (issued?.TemplateId != null)
            {
                var match = availableTemplates.FirstOrDefault(t => t.Id == issued.TemplateId);
                if (match != null)
                {
                    selectedTemplate = match;
                    OnTemplateSelected(match);
                }
            }
        }

        if (selectedTemplate == null || selectedTemplate.CertificateType != targetType)
        {
            var match = availableTemplates.FirstOrDefault(t => t.CertificateType == targetType)
                        ?? availableTemplates.FirstOrDefault();
            if (match != null)
            {
                selectedTemplate = match;
            }
        }

        OnTemplateSelected(selectedTemplate);
        if (selectedTemplate != null)
            await EnsureTemplateSanListsLoadedAsync(selectedTemplate);

        issuanceCertName = selectedNode.Name;

        var cdpUrls = ExtractExtensionUrls(selectedCert, "2.5.29.31");
        if (cdpUrls.Count > 0)
            issuanceCdpUrls = cdpUrls.Select(u => new IssuanceUrlEntry { Value = u }).ToList();

        var aiaUrls = ExtractExtensionUrls(selectedCert, "1.3.6.1.5.5.7.1.1");
        if (aiaUrls.Count > 0)
            issuanceAiaUrls = aiaUrls.Select(u => new IssuanceUrlEntry { Value = u }).ToList();

        isRenewMode = false;
    }

    private static List<string> ExtractExtensionUrls(X509Certificate2? cert, string oid)
    {
        var urls = new List<string>();
        if (cert == null) return urls;

        var ext = cert.Extensions[oid];
        if (ext == null) return urls;

        var data = ext.RawData;
        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == 0x86)
            {
                var len = data[i + 1];
                if (i + 2 + len <= data.Length)
                {
                    urls.Add(System.Text.Encoding.ASCII.GetString(data, i + 2, len));
                    i += 1 + len;
                }
            }
        }

        return urls;
    }

    private async Task ShowRenewDialog()
    {
        if (selectedNode == null || selectedCert == null) return;

        renewalOriginalCdpUrls = ExtractExtensionUrls(selectedCert, "2.5.29.31");
        renewalOriginalAiaUrls = ExtractExtensionUrls(selectedCert, "1.3.6.1.5.5.7.1.1");
        urlChangeWarnings.Clear();

        renewalSubjectDn = selectedCert.Subject;
        renewalSans.Clear();
        foreach (var san in subjectAltNames)
        {
            var trimmed = san.Trim();
            if (TryParseSan(trimmed, "URL=", SanType.Uri, out var entry) ||
                TryParseSan(trimmed, "URI:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "Uri:", SanType.Uri, out entry) ||
                TryParseSan(trimmed, "DNS Name=", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "DNS:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "Dns:", SanType.Dns, out entry) ||
                TryParseSan(trimmed, "RFC822 Name=", SanType.Email, out entry) ||
                TryParseSan(trimmed, "email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "Email:", SanType.Email, out entry) ||
                TryParseSan(trimmed, "IP Address=", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IP:", SanType.IpAddress, out entry) ||
                TryParseSan(trimmed, "IpAddress:", SanType.IpAddress, out entry))
            {
                renewalSans.Add(entry);
            }
        }

        // Determine the issuing CA
        int? issuingCaId = null;
        string? issuingCaName = null;

        await using var db = await DbFactory.CreateDbContextAsync();

        if (selectedNode.CertificateRole == "EndEntity")
        {
            var issued = await db.IssuedCertificates
                .Include(i => i.IssuingCaCertificate)
                .FirstOrDefaultAsync(i => i.Thumbprint == selectedNode.Thumbprint);
            if (issued != null)
            {
                issuingCaId = issued.IssuingCaCertificateId;
                issuingCaName = issued.IssuingCaCertificate.Name;
            }
        }
        else if (selectedNode.CertificateRole == "IntermediateCA")
        {
            var ca = await db.CaCertificates
                .Include(c => c.Parent)
                .FirstOrDefaultAsync(c => c.Thumbprint == selectedNode.Thumbprint);
            if (ca?.Parent != null)
            {
                issuingCaId = ca.ParentId;
                issuingCaName = ca.Parent.Name;
            }
        }
        else if (selectedNode.CertificateRole == "RootCA")
        {
            issuingCaId = null;
            issuingCaName = null;
        }

        // Set renewal mode BEFORE opening the dialog so OnTemplateSelected preserves SANs
        isRenewMode = true;
        await ShowIssuanceDialog(issuingCaId, issuingCaName);
        isRenewMode = true; // ShowIssuanceDialog resets it — restore

        // Pre-select a template matching the original cert's role
        var targetType = selectedNode.CertificateRole switch
        {
            "RootCA" => CertificateType.RootCa,
            "IntermediateCA" => CertificateType.IntermediateCa,
            "EndEntity" => CertificateType.EndEntityClient,
            _ => CertificateType.EndEntityClient
        };

        // Try to match the original cert's template if it had one
        if (selectedNode.CertificateRole == "EndEntity")
        {
            var issued = await db.IssuedCertificates.FindAsync(selectedNode.Id);
            if (issued?.TemplateId != null)
            {
                var match = availableTemplates.FirstOrDefault(t => t.Id == issued.TemplateId);
                if (match != null)
                {
                    selectedTemplate = match;
                    OnTemplateSelected(match);
                }
            }
        }

        // Fallback: match by cert type
        if (selectedTemplate == null || selectedTemplate.CertificateType != targetType)
        {
            var match = availableTemplates.FirstOrDefault(t => t.CertificateType == targetType)
                        ?? availableTemplates.FirstOrDefault();
            if (match != null)
            {
                selectedTemplate = match;
            }
        }

        // Always call OnTemplateSelected with isRenewMode=true to restore subject/SANs
        OnTemplateSelected(selectedTemplate);
        if (selectedTemplate != null)
            await EnsureTemplateSanListsLoadedAsync(selectedTemplate);

        issuanceCertName = selectedNode.Name + " (renewed)";
    }

    // --- Re-sign Methods ---

    private async Task ShowResignDialog()
    {
        if (selectedNode == null || selectedCert == null) return;

        // Load parent CA's NotAfter for clamping
        await using var db = await DbFactory.CreateDbContextAsync();
        DateTime? parentNotAfter = null;
        var caEntity = await db.CaCertificates.FindAsync(selectedNode.Id);
        if (caEntity?.ParentId != null)
        {
            var parent = await db.CaCertificates.FindAsync(caEntity.ParentId);
            parentNotAfter = parent?.NotAfter;
        }

        resignNotBefore = DateTime.UtcNow;
        // Default to the same duration as the original cert
        var originalDuration = selectedCert.NotAfter - selectedCert.NotBefore;
        var desiredNotAfter = DateTime.UtcNow.Add(originalDuration);

        // Clamp to parent's NotAfter if applicable
        if (parentNotAfter.HasValue && desiredNotAfter > parentNotAfter.Value)
            desiredNotAfter = parentNotAfter.Value;

        resignNotAfter = desiredNotAfter;
        resignPfxPassword = string.Empty;
        isResigning = false;
        resignDialogHidden = false;
    }

    private async Task ResignCertificateAsync()
    {
        if (selectedNode == null) return;

        isResigning = true;
        StateHasChanged();

        try
        {
            var request = new CertificateResignRequest
            {
                ExistingCertificateId = selectedNode.Id,
                EntityType = selectedNode.EntityType,
                NotBefore = resignNotBefore.HasValue ? new DateTimeOffset(resignNotBefore.Value, TimeSpan.Zero) : null,
                NotAfter = resignNotAfter.HasValue ? new DateTimeOffset(resignNotAfter.Value, TimeSpan.Zero) : null,
                PfxPassword = resignPfxPassword,
            };

            var result = await IssuanceService.ResignCertificateAsync(request);

            if (result.Success)
            {
                resignDialogHidden = true;
                ToastService.ShowCopyableSuccess($"Certificate re-signed (same key): {result.Thumbprint}");
                await LoadTrustDomainTreeAsync(TrustDomainId);
            }
            else
            {
                ToastService.ShowCopyableError(result.Error ?? "Unknown error");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Re-sign failed: {ex.Message}");
        }
        finally
        {
            isResigning = false;
            StateHasChanged();
        }
    }

    private static bool TryParseSan(string value, string prefix, SanType type, out IssuanceSanEntry entry)
    {
        if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            entry = new IssuanceSanEntry { Type = type, Value = value[prefix.Length..].Trim() };
            return true;
        }
        entry = null!;
        return false;
    }



    private static string? ExtractCrlAki(byte[] crlBytes)
    {
        try
        {
            var crlParser = new Org.BouncyCastle.X509.X509CrlParser();
            var crl = crlParser.ReadCrl(crlBytes);
            var akiOctets = crl.GetExtensionValue(Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityKeyIdentifier);
            if (akiOctets == null) return null;

            var aki = Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier.GetInstance(
                Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(akiOctets.GetOctets()));
            var keyId = aki.GetKeyIdentifier();
            return keyId != null ? Convert.ToHexString(keyId) : null;
        }
        catch
        {
            return null;
        }
    }

    private static string GetCertTypeLabel(CertificateType ct) => ct switch
    {
        CertificateType.RootCa => "Root CA",
        CertificateType.IntermediateCa => "Intermediate CA",
        CertificateType.EndEntityClient => "Client",
        CertificateType.EndEntityServer => "Server",
        _ => ct.ToString()
    };

    public class TrustDomainOption
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public List<BaseUrlViewModel> BaseUrls { get; set; } = new();
    }

    public class CaSelectOption
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public bool IsRoot { get; set; }
        public string DisplayName => IsRoot ? $"[Root] {Name}" : $"[Intermediate] {Name}";
    }

    public class IssuanceSanEntry
    {
        public SanType Type { get; set; } = SanType.Uri;
        public string Value { get; set; } = string.Empty;
    }

    public class IssuanceUrlEntry
    {
        public string Value { get; set; } = string.Empty;
    }

    public class SanListPickerItem
    {
        public SanType Type { get; set; }
        public string Value { get; set; } = string.Empty;
        public bool Selected { get; set; }
    }

    private async Task ShowRevokeDialog()
    {
        if (selectedNode == null) return;
        selectedRevokeReason = revokeReasonOptions[0];
        isRevoking = false;
        revokeImpacts = selectedNode.EntityType == "CaCertificate"
            ? await ManagementService.GetCaRevokeImpactAsync(selectedNode.Id)
            : null;
        revokeDialogHidden = false;
    }

    private async Task RevokeCertificateAsync()
    {
        if (selectedNode == null) return;

        isRevoking = true;
        StateHasChanged();

        try
        {
            var revokeResult = await ManagementService.RevokeAsync(
                selectedNode.Id, selectedNode.EntityType, selectedRevokeReason.Code);

            revokeDialogHidden = true;

            if (revokeResult.Success)
            {
                if (revokeResult.CrlNumber.HasValue)
                {
                    ToastService.ShowCopyableSuccess(
                        $"Certificate '{selectedNode.Name}' revoked (reason: {selectedRevokeReason.Label}). CRL #{revokeResult.CrlNumber} generated with {revokeResult.RevokedCount} revocation(s).");
                }
                else
                {
                    ToastService.ShowCopyableSuccess(
                        $"Certificate '{selectedNode.Name}' revoked (reason: {selectedRevokeReason.Label}).");
                }

                if (!string.IsNullOrEmpty(revokeResult.Error))
                    ToastService.ShowCopyableError(revokeResult.Error);
            }
            else
            {
                ToastService.ShowCopyableError(revokeResult.Error ?? "Revocation failed.");
            }

            await LoadTrustDomainTreeAsync(TrustDomainId);
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Revocation failed: {ex.Message}");
        }
        finally
        {
            isRevoking = false;
            StateHasChanged();
        }
    }

    public record RevokeReasonOption(int Code, string Label);

    public record TreeStatusFilterOption(string Label, CertificateStatus? Value, string? RoleOnly = null);

    private string IdentitySummary()
    {
        if (string.IsNullOrWhiteSpace(issuanceSubjectDn)) return "(empty)";
        var cn = ExtractCommonName(issuanceSubjectDn);
        return string.IsNullOrEmpty(cn) ? "(empty)" : cn;
    }

    private string ExtensionsSummary()
    {
        var parts = new List<string>();
        if (selectedTemplate?.IncludeCdp == true)
            parts.Add($"{issuanceCdpUrls.Count(c => !string.IsNullOrWhiteSpace(c.Value))} CDP");
        if (selectedTemplate?.IncludeAia == true)
            parts.Add($"{issuanceAiaUrls.Count(a => !string.IsNullOrWhiteSpace(a.Value))} AIA");
        parts.Add($"{issuanceSans.Count(s => !string.IsNullOrWhiteSpace(s.Value))} SAN");
        return string.Join(" · ", parts);
    }

    private string KeyStorageSummary() => issuanceKeyStorage switch
    {
        "vault-transit" => "Vault Transit",
        "gcp-kms" => "GCP Cloud KMS",
        _ => "Local (PFX)"
    };

    private static string ExtractCommonName(string subjectDn)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            subjectDn, @"CN\s*=\s*([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : subjectDn.Trim();
    }

    private IEnumerable<CertificateChainNodeViewModel> VisibleRoots() =>
        treeNodes.Where(IsNodeVisible);

    private bool IsNodeVisible(CertificateChainNodeViewModel node) =>
        !IsTreeFilterActive || visibleNodes.Contains(node);

    private void OnTreeFilterChanged()
    {
        RecomputeVisibleNodes();
        treeVersion++;
    }

    private void OnTreeStatusFilterChanged(TreeStatusFilterOption? option)
    {
        selectedTreeStatusFilter = option ?? treeStatusFilterOptions[0];
        RecomputeVisibleNodes();
        treeVersion++;
    }

    private void ClearTreeFilter()
    {
        treeFilterText = string.Empty;
        selectedTreeStatusFilter = treeStatusFilterOptions[0];
        RecomputeVisibleNodes();
        treeVersion++;
    }

    private void RecomputeVisibleNodes()
    {
        visibleNodes = new HashSet<CertificateChainNodeViewModel>();
        totalNodeCount = 0;
        visibleNodeCount = 0;

        foreach (var root in treeNodes)
            ComputeVisibility(root);
    }

    private bool ComputeVisibility(CertificateChainNodeViewModel node)
    {
        var crlFocus = selectedTreeStatusFilter.RoleOnly == "CRL";
        var nodeCountsTowardTotal = crlFocus
            ? node.CertificateRole == "CRL"
            : node.CertificateRole != "CRL";
        if (nodeCountsTowardTotal)
            totalNodeCount++;

        var selfMatches = MatchesFilter(node);
        var anyChildMatches = false;
        foreach (var child in node.Children)
        {
            if (ComputeVisibility(child))
                anyChildMatches = true;
        }

        var visible = selfMatches || anyChildMatches;
        if (visible)
        {
            visibleNodes.Add(node);
            if (selfMatches && nodeCountsTowardTotal)
                visibleNodeCount++;
        }
        return visible;
    }

    private bool MatchesFilter(CertificateChainNodeViewModel node)
    {
        // Role-only filter (e.g. "CRLs only"): match only nodes of that role.
        // Parents become visible via child-matches in ComputeVisibility.
        if (selectedTreeStatusFilter.RoleOnly != null)
        {
            if (node.CertificateRole != selectedTreeStatusFilter.RoleOnly) return false;
        }
        else if (selectedTreeStatusFilter.Value != null)
        {
            // Status filter: only applies to non-CRL nodes
            if (node.CertificateRole == "CRL") return false;
            if (node.Status != selectedTreeStatusFilter.Value) return false;
        }

        if (!string.IsNullOrWhiteSpace(treeFilterText))
        {
            var needle = treeFilterText.Trim();
            return node.Name.Contains(needle, StringComparison.OrdinalIgnoreCase)
                || node.Subject.Contains(needle, StringComparison.OrdinalIgnoreCase)
                || node.Thumbprint.StartsWith(needle, StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    public void Dispose()
    {
        TimeDisplay.OnChanged -= StateHasChanged;
        dotNetRef?.Dispose();
    }
}
