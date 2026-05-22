#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigil.Vault.Hosting;

var builder = DistributedApplication.CreateBuilder(args);

// Vault with persistent file storage + Transit engine + signing keys.
// Persistent mode survives container restarts (init state stored at
// %LOCALAPPDATA%/Sigil/vault-vault-init.json, data in Docker volume vault-vault-data).
var vault = builder.AddVaultDev("vault", persistent: true)
    .WithTransitEngine(
        new TransitKeySpec("sigil-rsa-4096", "rsa-4096"),
        new TransitKeySpec("sigil-ecdsa-p384", "ecdsa-p384"));

// Certificate server (static file host for CRLs and certs — always runs as a project)
var certServer = builder.AddProject<Projects.Sigil_Certificate_Server>("certificate-server");

// Sigil hosting mode: "project" (default), "docker", or "docker-gcp"
// Set via env var Sigil__HostMode in launch profile.
var hostMode = builder.Configuration["Sigil:HostMode"]?.ToLowerInvariant() ?? "project";

// Signing provider: "vault-transit" (default) or "gcp-kms"
// When "gcp-kms", Vault is still started (may be used for other keys) but Sigil signs via GCP Cloud KMS.
var signingProvider = builder.Configuration["Sigil:SigningProvider"]?.ToLowerInvariant() ?? "vault-transit";

IResourceBuilder<IResourceWithEndpoints> sigil;

switch (hostMode)
{
    case "docker-gcp":
    case "docker":
    {
        var dockerfile = hostMode == "docker-gcp" ? "Sigil/Dockerfile.gcp" : "Sigil/Dockerfile";

        var dockerResource = builder.AddDockerfile("sigil", "..", dockerfile)
            .WithHttpEndpoint(port: 5200, targetPort: 5200)
            .WithHttpsEndpoint(port: 7200, targetPort: 7200)
            .WithHttpsCertificateConfiguration(ctx =>
            {
                // Aspire injects its trusted dev cert — Kestrel picks it up via these env vars
                if (ctx.Password is null)
                {
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Path"] = ctx.CertificatePath;
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__KeyPath"] = ctx.KeyPath;
                }
                else
                {
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Path"] = ctx.PfxPath;
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Password"] = ctx.Password;
                }
                return Task.CompletedTask;
            })
            .WithEnvironment("ASPNETCORE_URLS", "https://+:7200;http://+:5200")
            .WithReference(vault)
            .WithEnvironment("ConnectionStrings__SigilDb", "Host=host.docker.internal;Database=sigil;Username=sigil;Password=sigil_pass;Search Path=sigil")
            .WithEnvironment("Vault__Address", vault.Resource.PrimaryEndpoint)
            .WithEnvironment("Vault__Token", "root-token")
            .WithEnvironment("Signing__Provider", signingProvider)
            .WithEnvironment("Signing__AvailableProviders__0", "local")
            .WithEnvironment("Signing__AvailableProviders__1", "vault-transit");

        if (hostMode == "docker-gcp")
            dockerResource.WithVolume("sigil-gcloud-config", "/root/.config/gcloud");

        // GCP KMS configuration — project/location/keyring passed via env vars
        if (signingProvider == "gcp-kms")
        {
            var gcpProject = builder.Configuration["GcpKms:ProjectId"] ?? "";
            var gcpLocation = builder.Configuration["GcpKms:LocationId"] ?? "us-central1";
            var gcpKeyRing = builder.Configuration["GcpKms:KeyRingId"] ?? "sigil";

            dockerResource
                .WithEnvironment("GcpKms__ProjectId", gcpProject)
                .WithEnvironment("GcpKms__LocationId", gcpLocation)
                .WithEnvironment("GcpKms__KeyRingId", gcpKeyRing);
        }

        sigil = dockerResource;
        break;
    }

    default: // "project"
        var projectResource = builder.AddProject<Projects.Sigil>("sigil")
            .WithReference(vault)
            .WithEnvironment("Vault__Address", vault.Resource.PrimaryEndpoint)
            .WithEnvironment("Vault__Token", "root-token")
            .WithEnvironment("Signing__Provider", signingProvider)
            .WithEnvironment("Signing__AvailableProviders__0", "local")
            .WithEnvironment("Signing__AvailableProviders__1", "vault-transit");

        // GCP KMS configuration for project mode
        if (signingProvider == "gcp-kms")
        {
            var gcpProject = builder.Configuration["GcpKms:ProjectId"] ?? "";
            var gcpLocation = builder.Configuration["GcpKms:LocationId"] ?? "us-central1";
            var gcpKeyRing = builder.Configuration["GcpKms:KeyRingId"] ?? "sigil";

            projectResource
                .WithEnvironment("GcpKms__ProjectId", gcpProject)
                .WithEnvironment("GcpKms__LocationId", gcpLocation)
                .WithEnvironment("GcpKms__KeyRingId", gcpKeyRing);
        }

        sigil = projectResource;
        break;
}

builder.Build().Run();
