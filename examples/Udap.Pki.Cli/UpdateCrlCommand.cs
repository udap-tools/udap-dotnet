using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Cloud.Storage.V1;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Spectre.Console;
using Spectre.Console.Cli;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Udap.Pki.Cli;

public class UpdateCrlCommand : AsyncCommand<UpdateCrlSettings>
{
    protected override async Task<int> ExecuteAsync(CommandContext context, UpdateCrlSettings settings, CancellationToken cancellationToken)
    {
        var password = ResolvePassword(settings);
        return await UpdateCrl(settings.Type, password, settings.IsProduction, settings.Days, "PrivatePkiStore");
    }

    internal static string ResolvePassword(UpdateCrlSettings settings)
    {
        if (!string.IsNullOrEmpty(settings.Password))
            return settings.Password;

        var envValue = Environment.GetEnvironmentVariable("CA_P12_PASSWORD");
        if (!string.IsNullOrEmpty(envValue))
            return envValue;

        if (!Console.IsInputRedirected)
        {
            return AnsiConsole.Prompt(
                new TextPrompt<string>("Enter the [yellow]CA P12 password[/]:")
                    .PromptStyle("red").Secret());
        }

        throw new InvalidOperationException(
            "No password provided. Use --password, set CA_P12_PASSWORD env var, or run interactively.");
    }

    internal static async Task<int> UpdateCrl(CrlType type, string password, bool isProduction, int days, string configSectionName = "PrivatePkiStore")
    {
        if (isProduction)
        {
            AnsiConsole.MarkupLine("[bold green]Running in PRODUCTION mode[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("[bold yellow]Running in TEST mode (default)[/]");
        }

        AnsiConsole.MarkupLine($"[green]Updating {type} CRL ({configSectionName})[/]");

        // Load configuration
        var config = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false)
            .Build();
        var gcpPkiConfig = config.GetSection(configSectionName).Get<PrivatePkiStoreConfig>()!;
        var publicCertStoreConfig = config.GetSection("PublicCertStore").Get<PublicCertStoreConfig>()!;

        // Select paths based on type
        string p12Path, crlPath;
        if (type == CrlType.CA)
        {
            p12Path = gcpPkiConfig.CaP12Path;
            crlPath = gcpPkiConfig.CaCrlPath;
        }
        else
        {
            p12Path = gcpPkiConfig.SubCaP12Path;
            crlPath = gcpPkiConfig.SubCaCrlPath;
        }

        // Download CA P12
        var storage = StorageClient.Create();
        using var caP12Stream = new MemoryStream();
        await storage.DownloadObjectAsync(gcpPkiConfig.CaBucket, p12Path, caP12Stream);
        caP12Stream.Position = 0;

        // Load CA certificate
        var caCert = X509CertificateLoader.LoadPkcs12(caP12Stream.ToArray(), password, X509KeyStorageFlags.Exportable);

        // Download CRL
        using var crlStream = new MemoryStream();
        await storage.DownloadObjectAsync(gcpPkiConfig.CaBucket, crlPath, crlStream);
        crlStream.Position = 0;
        var crlBytes = crlStream.ToArray();

        // Parse CRL and show version
        var crlParser = new X509CrlParser();
        var crl = crlParser.ReadCrl(crlBytes);
        AnsiConsole.MarkupLine($"[blue]Current CRL number:[/] {GetCurrentCrlNumber(crl)}");

        // Generate new CRL
        var newCrlBytes = GenerateNewCrl(caCert, password, crlBytes, days);

        if (isProduction)
        {
            using var uploadStream = new MemoryStream(newCrlBytes);
            await storage.UploadObjectAsync(gcpPkiConfig.CaBucket, crlPath, "application/pkix-crl", uploadStream);

            AnsiConsole.MarkupLine("[green]New CRL uploaded successfully![/]");

            var publicCrlObjectName = $"{publicCertStoreConfig.CrlPath}/{Path.GetFileName(crlPath)}";
            using var publicUploadStream = new MemoryStream(newCrlBytes);

            await storage.UploadObjectAsync(
                publicCertStoreConfig.CrlBucket,
                publicCrlObjectName,
                "application/pkix-crl",
                publicUploadStream);

            AnsiConsole.MarkupLine($"[green]New CRL also uploaded to public bucket: {publicCertStoreConfig.CrlBucket}/{publicCrlObjectName}[/]");

            // Invalidate CDN cache
            if (!string.IsNullOrEmpty(publicCertStoreConfig.CdnUrlMapName))
            {
                await InvalidateCdnCacheAsync(publicCertStoreConfig.CdnUrlMapName, $"/{publicCrlObjectName}");
            }
        }
        else
        {
            // Write CRL to disk for inspection
            var crlFilePath = type == CrlType.CA ? "c://temp/CA.crl" : "c://temp/SubCA.crl";
            await File.WriteAllBytesAsync(crlFilePath, newCrlBytes);
            AnsiConsole.MarkupLine($"[yellow]New CRL written to disk at:[/] {crlFilePath}");
        }

        return 0;
    }

    public static byte[] GenerateNewCrl(X509Certificate2 caCert, string caPassword, byte[] previousCrlBytes, int days)
    {
        var (bouncyCertificate, privateKey) = GetCertificateData(caCert);

        var crlParser = new X509CrlParser();
        var previousCrl = crlParser.ReadCrl(previousCrlBytes);
        var nextCrlNumber = GetNextCrlNumber(previousCrl);

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(bouncyCertificate.SubjectDN);
        var now = DateTime.UtcNow;
        crlGen.SetThisUpdate(now);
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(days));

        foreach (X509CrlEntry entry in previousCrl.GetRevokedCertificates() ?? Enumerable.Empty<X509CrlEntry>())
        {
            var reasonExt = entry.GetExtensionValue(X509Extensions.ReasonCode);

            if (reasonExt != null)
            {
                crlGen.AddCrlEntry(
                    entry.SerialNumber,
                    entry.RevocationDate,
                    new X509Extensions(
                        new DerObjectIdentifier[] { X509Extensions.ReasonCode },
                        new[] { new Org.BouncyCastle.Asn1.X509.X509Extension(false, reasonExt) }
                    )
                );
            }
            else
            {
                crlGen.AddCrlEntry(
                    entry.SerialNumber,
                    entry.RevocationDate,
                    null
                );
            }
        }
        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, X509ExtensionUtilities.CreateAuthorityKeyIdentifier(bouncyCertificate.GetPublicKey()));
        crlGen.AddExtension(X509Extensions.CrlNumber, false, nextCrlNumber);

        var sigFactory = new Asn1SignatureFactory("SHA256WithRSAEncryption", privateKey);
        var crl = crlGen.Generate(sigFactory);

        return crl.GetEncoded();
    }

    private static (X509Certificate bouncyCertificate, AsymmetricKeyParameter privateKey) GetCertificateData(
        X509Certificate2 p12Certificate)
    {
        var bouncyCertificate = DotNetUtilities.FromX509Certificate(p12Certificate);
        using var rsaPrivateKey = p12Certificate.GetRSAPrivateKey();
        if (rsaPrivateKey == null)
            throw new InvalidOperationException("Certificate does not have an RSA private key.");

        RSA exportableRsa;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && rsaPrivateKey is RSACng cng)
        {
            if (!cng.Key.ExportPolicy.HasFlag(CngExportPolicies.AllowExport))
            {
                throw new InvalidOperationException(
                    "The private key is not exportable. Re-create the P12 with an exportable key.");
            }
            var tempPassword = Guid.NewGuid().ToString("N");
            var encryptedPrivateKeyBytes = cng.ExportEncryptedPkcs8PrivateKey(
                tempPassword,
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));
            exportableRsa = RSA.Create();
            exportableRsa.ImportEncryptedPkcs8PrivateKey(tempPassword, encryptedPrivateKeyBytes, out _);
        }
        else
        {
            var privateKeyBytes = rsaPrivateKey.ExportPkcs8PrivateKey();
            exportableRsa = RSA.Create();
            exportableRsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
        }

        var privateKey = DotNetUtilities.GetKeyPair(exportableRsa).Private;
        exportableRsa.Dispose();
        return (bouncyCertificate, privateKey);
    }

    public static string GetCurrentCrlNumber(X509Crl crl)
    {
        var crlNumExt = crl.GetExtensionValue(X509Extensions.CrlNumber);

        if (crlNumExt == null)
        {
            return BigInteger.Zero.ToString();
        }

        var asn1Object = X509ExtensionUtilities.FromExtensionValue(crlNumExt);
        return DerInteger.GetInstance(asn1Object).PositiveValue.ToString();
    }

    public static CrlNumber GetNextCrlNumber(X509Crl crl)
    {
        var crlNumExt = crl.GetExtensionValue(X509Extensions.CrlNumber);

        if (crlNumExt == null)
        {
            // If no CRL number, start at 1
            return new CrlNumber(BigInteger.One);
        }

        var asn1Object = X509ExtensionUtilities.FromExtensionValue(crlNumExt);
        var prevCrlNum = DerInteger.GetInstance(asn1Object).PositiveValue;
        var nextCrlNum = prevCrlNum.Add(BigInteger.One);
        AnsiConsole.MarkupLine($"[blue]New CRL number:[/] {nextCrlNum}");

        return new CrlNumber(nextCrlNum);
    }

    private static async Task InvalidateCdnCacheAsync(string urlMapName, string path)
    {
        AnsiConsole.MarkupLine($"[blue]Invalidating CDN cache for path:[/] {path}");

        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "gcloud",
                ArgumentList = { "compute", "url-maps", "invalidate-cdn-cache", urlMapName, "--path", path },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };

        process.Start();
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        if (process.ExitCode == 0)
        {
            AnsiConsole.MarkupLine("[green]CDN cache invalidation requested successfully.[/]");
        }
        else
        {
            AnsiConsole.MarkupLine($"[red]CDN cache invalidation failed (exit code {process.ExitCode}):[/]");
            AnsiConsole.MarkupLine($"[red]{stderr}[/]");
        }

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            AnsiConsole.MarkupLine(stdout.TrimEnd());
        }
    }
}
