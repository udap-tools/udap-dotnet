CREATE TABLE IF NOT EXISTS "__EFMigrationsHistory" (
    "MigrationId" TEXT NOT NULL CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY,
    "ProductVersion" TEXT NOT NULL
);

BEGIN TRANSACTION;

CREATE TABLE "UdapCommunities" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_UdapCommunities" PRIMARY KEY AUTOINCREMENT,
    "Name" TEXT NOT NULL,
    "Enabled" INTEGER NOT NULL,
    "Default" INTEGER NOT NULL
);

CREATE TABLE "UdapRootCertificates" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_UdapRootCertificates" PRIMARY KEY AUTOINCREMENT,
    "Enabled" INTEGER NOT NULL,
    "Name" TEXT NOT NULL,
    "X509Certificate" TEXT NOT NULL,
    "Thumbprint" TEXT NOT NULL,
    "BeginDate" TEXT NOT NULL,
    "EndDate" TEXT NOT NULL
);

CREATE TABLE "UdapAnchors" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_UdapAnchors" PRIMARY KEY AUTOINCREMENT,
    "Enabled" INTEGER NOT NULL,
    "Name" TEXT NOT NULL,
    "X509Certificate" TEXT NOT NULL,
    "Thumbprint" TEXT NOT NULL,
    "BeginDate" TEXT NOT NULL,
    "EndDate" TEXT NOT NULL,
    "CommunityId" INTEGER NOT NULL,
    CONSTRAINT "FK_Anchor_Communities" FOREIGN KEY ("CommunityId") REFERENCES "UdapCommunities" ("Id") ON DELETE CASCADE
);

CREATE TABLE "UdapCertifications" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_UdapCertifications" PRIMARY KEY AUTOINCREMENT,
    "Name" TEXT NOT NULL,
    "CommunityId" INTEGER NULL,
    CONSTRAINT "FK_UdapCertifications_UdapCommunities_CommunityId" FOREIGN KEY ("CommunityId") REFERENCES "UdapCommunities" ("Id")
);

CREATE TABLE "UdapAnchorCertification" (
    "AnchorId" INTEGER NOT NULL,
    "CertificationId" INTEGER NOT NULL,
    CONSTRAINT "PK_UdapAnchorCertification" PRIMARY KEY ("AnchorId", "CertificationId"),
    CONSTRAINT "FK_AnchorCertification_Anchor" FOREIGN KEY ("AnchorId") REFERENCES "UdapAnchors" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_AnchorCertification_Certification" FOREIGN KEY ("CertificationId") REFERENCES "UdapCertifications" ("Id") ON DELETE CASCADE
);

CREATE TABLE "UdapCommunityCertification" (
    "CommunityId" INTEGER NOT NULL,
    "CertificationId" INTEGER NOT NULL,
    CONSTRAINT "PK_UdapCommunityCertification" PRIMARY KEY ("CommunityId", "CertificationId"),
    CONSTRAINT "FK_CommunityCertification_Certification" FOREIGN KEY ("CertificationId") REFERENCES "UdapCertifications" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_CommunityCertification_Community" FOREIGN KEY ("CommunityId") REFERENCES "UdapCommunities" ("Id")
);

CREATE INDEX "IX_UdapAnchorCertification_CertificationId" ON "UdapAnchorCertification" ("CertificationId");

CREATE INDEX "IX_UdapAnchors_CommunityId" ON "UdapAnchors" ("CommunityId");

CREATE INDEX "IX_UdapCertifications_CommunityId" ON "UdapCertifications" ("CommunityId");

CREATE INDEX "IX_UdapCommunityCertification_CertificationId" ON "UdapCommunityCertification" ("CertificationId");

INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES ('20221208223455_InitialUdap', '7.0.0');

COMMIT;

