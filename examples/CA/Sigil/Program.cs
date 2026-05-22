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
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Serilog;
using Sigil.Components;
using Microsoft.Extensions.Options;
using Sigil.Common.Data;
using Sigil.ServiceDefaults;
using Sigil.Common.Data.Entities;
using Hangfire;
using Hangfire.Dashboard;
using Hangfire.PostgreSql;
using Hangfire.Storage;
using Sigil.Common.Services;
using Sigil.Common.Services.Jobs;
using Sigil.Common.Services.Signing;
using Sigil.Common.Validators;
using Sigil.Gcp;
using Sigil.Services;
using Sigil.Vault;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Aspire service defaults (active when running under Aspire AppHost)
    var useServiceDefaults = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"] is not null;
    if (useServiceDefaults)
    {
        builder.AddServiceDefaults();
    }

    // Serilog
    builder.Host.UseSerilog((context, config) => config
        .ReadFrom.Configuration(context.Configuration)
        .WriteTo.Console());

    // PostgreSQL
    builder.Services.AddDbContextFactory<SigilDbContext>(options =>
        options.UseNpgsql(builder.Configuration.GetConnectionString("SigilDb")));

    // Services
    builder.Services.AddScoped<CertificateImportService>();
    builder.Services.AddScoped<CertificateParsingService>();
    builder.Services.AddScoped<Asn1ParsingService>();
    builder.Services.AddScoped<CrlImportService>();
    builder.Services.AddScoped<ChainValidationService>();
    builder.Services.AddScoped<CertificateExportService>();
    builder.Services.AddScoped<DashboardService>();
    builder.Services.AddScoped<TemplateService>();
    builder.Services.AddScoped<TrustDomainService>();
    builder.Services.AddScoped<CertificateManagementService>();
    builder.Services.AddScoped<CertificatePublishingService>();
    builder.Services.AddSingleton<IssuanceValidator>();
    builder.Services.AddScoped<SanListService>();
    builder.Services.AddHttpClient("SigilCrl");
    builder.Services.AddHttpClient();

    // Signing provider configuration
    builder.Services.Configure<SigningProviderOptions>(
        builder.Configuration.GetSection("Signing"));
    builder.Services.Configure<VaultTransitOptions>(
        builder.Configuration.GetSection("Vault"));
    builder.Services.Configure<GcpKmsOptions>(
        builder.Configuration.GetSection("GcpKms"));
    builder.Services.AddHttpClient("VaultTransit");
    builder.Services.AddSingleton<LocalSigningProvider>();
    builder.Services.AddSingleton<VaultTransitSigningProvider>();
    builder.Services.AddSingleton<GcpKmsSigningProvider>();
    builder.Services.AddSingleton<ISigningProvider>(sp =>
    {
        var options = sp.GetRequiredService<IOptions<SigningProviderOptions>>().Value;
        return options.Provider switch
        {
            "vault-transit" => sp.GetRequiredService<VaultTransitSigningProvider>(),
            "gcp-kms" => sp.GetRequiredService<GcpKmsSigningProvider>(),
            _ => sp.GetRequiredService<LocalSigningProvider>()
        };
    });
    builder.Services.AddScoped<CertificateIssuanceService>();
    builder.Services.AddScoped<CrlGenerationService>();
    builder.Services.AddScoped<CrlAutoRenewalJob>();
    builder.Services.AddScoped<Sigil.UI.Services.TimeDisplayService>();
    builder.Services.AddScoped<Sigil.UI.Services.IssuancePasswordCache>();

    // System status — populate from existing options sections
    builder.Services.AddOptions<SystemStatusOptions>().Configure<
        IOptions<SigningProviderOptions>,
        IOptions<VaultTransitOptions>,
        IOptions<GcpKmsOptions>>((status, signing, vault, gcp) =>
    {
        status.DefaultProvider = signing.Value.Provider;
        status.AvailableProviders = signing.Value.AvailableProviders;
        status.VaultAddress = vault.Value.Address;
        status.VaultToken = vault.Value.Token;
        status.GcpProjectId = gcp.Value.ProjectId;
    });
    builder.Services.AddSingleton<SystemStatusService>();

    // Hangfire
    builder.Services.AddHangfire(config => config
        .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
        .UseSimpleAssemblyNameTypeSerializer()
        .UseRecommendedSerializerSettings()
        .UsePostgreSqlStorage(options =>
            options.UseNpgsqlConnection(builder.Configuration.GetConnectionString("SigilDb")),
            new PostgreSqlStorageOptions { SchemaName = "sigil" }));
    builder.Services.AddHangfireServer();
    builder.Services.AddSingleton<IRecurringJobScheduler, HangfireRecurringJobScheduler>();

    // Blazor Server + Fluent UI
    builder.Services.AddRazorComponents()
        .AddInteractiveServerComponents();
    builder.Services.AddFluentUIComponents();

    var app = builder.Build();

    // Run migrations + seed data
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<SigilDbContext>();
        await db.Database.MigrateAsync();
        await SeedTemplatesAsync(db);
    }

    app.UseSerilogRequestLogging(options =>
    {
        options.GetLevel = (httpContext, elapsed, ex) =>
        {
            var path = httpContext.Request.Path.Value ?? "";
            if (path.StartsWith("/_blazor") ||
                path.StartsWith("/_framework") ||
                path.StartsWith("/_content") ||
                path.StartsWith("/css") ||
                path == "/favicon.ico")
            {
                return Serilog.Events.LogEventLevel.Debug;
            }

            return Serilog.Events.LogEventLevel.Information;
        };
    });

    // Hangfire dashboard (Sigil is a dev/internal tool — open access)
    app.MapHangfireDashboard("/hangfire", new DashboardOptions
    {
        Authorization = [new AllowAllDashboardAuthorizationFilter()]
    });

    // Register recurring CRL auto-renewal job only if not already configured
    // (preserves cron schedule edited via the Jobs UI across restarts)
    using (var connection = JobStorage.Current.GetConnection())
    {
        var existingJobs = connection.GetRecurringJobs();
        if (!existingJobs.Any(j => j.Id == "crl-auto-renewal"))
        {
            var crlCron = builder.Configuration["Hangfire:CrlRenewalCron"] ?? Cron.Hourly();
            RecurringJob.AddOrUpdate<CrlAutoRenewalJob>(
                "crl-auto-renewal",
                job => job.ExecuteAsync(CancellationToken.None),
                crlCron);
        }
    }

    app.UseStaticFiles();
    app.MapStaticAssets();
    app.UseAntiforgery();
    if (useServiceDefaults)
    {
        app.MapDefaultEndpoints(); // Aspire health checks (/health, /alive)
    }

    app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode()
        .AddAdditionalAssemblies(
            typeof(FluentButton).Assembly,
            typeof(Sigil.UI.Components.Pages.Home).Assembly);

    // Download endpoints
    app.MapGet("/api/ca/{id}/download/cer", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var ca = await db.CaCertificates.FindAsync(id);
        if (ca == null) return Results.NotFound();

        var cerBytes = Encoding.UTF8.GetBytes(ca.X509CertificatePem);
        return Results.File(cerBytes, "application/x-pem-file", $"{ca.Name}.cer");
    });

    app.MapGet("/api/ca/{id}/download/p12", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var ca = await db.CaCertificates.FindAsync(id);
        if (ca?.EncryptedPfxBytes == null) return Results.NotFound("No private key available");

        return Results.File(ca.EncryptedPfxBytes, "application/x-pkcs12", $"{ca.Name}.p12");
    });

    app.MapGet("/api/issued/{id}/download/cer", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var cert = await db.IssuedCertificates.FindAsync(id);
        if (cert == null) return Results.NotFound();

        var cerBytes = Encoding.UTF8.GetBytes(cert.X509CertificatePem);
        return Results.File(cerBytes, "application/x-pem-file", $"{cert.Name}.cer");
    });

    app.MapGet("/api/issued/{id}/download/p12", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var cert = await db.IssuedCertificates.FindAsync(id);
        if (cert?.EncryptedPfxBytes == null) return Results.NotFound("No private key available");

        return Results.File(cert.EncryptedPfxBytes, "application/x-pkcs12", $"{cert.Name}.p12");
    });

    app.MapGet("/api/crl/{id}/download", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var crl = await db.Crls.FindAsync(id);
        if (crl == null) return Results.NotFound();

        var fileName = crl.FileName ?? $"crl-{crl.CrlNumber}.crl";
        return Results.File(crl.RawBytes, "application/pkix-crl", fileName);
    });

    // PEM download endpoints
    app.MapGet("/api/ca/{id}/download/pem", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var ca = await db.CaCertificates.FindAsync(id);
        if (ca == null) return Results.NotFound();

        var pemBytes = Encoding.UTF8.GetBytes(ca.X509CertificatePem);
        return Results.File(pemBytes, "application/x-pem-file", $"{ca.Name}.pem");
    });

    app.MapGet("/api/issued/{id}/download/pem", async (int id, IDbContextFactory<SigilDbContext> dbFactory) =>
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var cert = await db.IssuedCertificates.FindAsync(id);
        if (cert == null) return Results.NotFound();

        var pemBytes = Encoding.UTF8.GetBytes(cert.X509CertificatePem);
        return Results.File(pemBytes, "application/x-pem-file", $"{cert.Name}.pem");
    });

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

static async Task SeedTemplatesAsync(SigilDbContext db)
{
    if (await db.CertificateTemplates.AnyAsync(t => t.IsPreset))
        return;

    db.CertificateTemplates.AddRange(
        new CertificateTemplate
        {
            Name = "Root CA",
            Description = "Self-signed Root Certificate Authority with 10-year validity.",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA",
            KeySize = 4096,
            ValidityDays = 3650,
            KeyUsageFlags = (int)(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign),
            IsKeyUsageCritical = true,
            IsBasicConstraintsCa = true,
            IsBasicConstraintsCritical = true,
            PathLengthConstraint = null,
            HashAlgorithm = "SHA256",
            IsPreset = true,
        },
        new CertificateTemplate
        {
            Name = "Intermediate CA",
            Description = "Intermediate Certificate Authority signed by a Root CA, 5-year validity.",
            CertificateType = CertificateType.IntermediateCa,
            KeyAlgorithm = "RSA",
            KeySize = 4096,
            ValidityDays = 1825,
            KeyUsageFlags = (int)(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign),
            IsKeyUsageCritical = true,
            IsBasicConstraintsCa = true,
            IsBasicConstraintsCritical = true,
            PathLengthConstraint = 0,
            HashAlgorithm = "SHA256",
            IncludeCdp = true,
            IncludeAia = true,
            SubjectAltNameTypes = "URI",
            IsPreset = true,
        },
        new CertificateTemplate
        {
            Name = "UDAP Client",
            Description = "End-entity client certificate for UDAP dynamic client registration.",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 730,
            KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
            IsKeyUsageCritical = true,
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.2",
            IsBasicConstraintsCa = false,
            IsBasicConstraintsCritical = true,
            HashAlgorithm = "SHA256",
            IncludeCdp = true,
            IncludeAia = true,
            SubjectAltNameTypes = "URI",
            IsPreset = true,
        },
        new CertificateTemplate
        {
            Name = "SSL Server",
            Description = "End-entity TLS server certificate for HTTPS endpoints.",
            CertificateType = CertificateType.EndEntityServer,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365,
            KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
            IsKeyUsageCritical = true,
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            IsBasicConstraintsCa = false,
            IsBasicConstraintsCritical = true,
            HashAlgorithm = "SHA256",
            IncludeCdp = true,
            SubjectAltNameTypes = "DNS",
            IsPreset = true,
        }
    );

    await db.SaveChangesAsync();
}

/// <summary>
/// Allows all requests to the Hangfire dashboard. Used in development only.
/// </summary>
class AllowAllDashboardAuthorizationFilter : IDashboardAuthorizationFilter
{
    public bool Authorize(DashboardContext context) => true;
}
