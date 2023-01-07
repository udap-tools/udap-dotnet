IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
BEGIN
    CREATE TABLE [__EFMigrationsHistory] (
        [MigrationId] nvarchar(150) NOT NULL,
        [ProductVersion] nvarchar(32) NOT NULL,
        CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
    );
END;
GO

BEGIN TRANSACTION;
GO

CREATE TABLE [UdapCommunities] (
    [Id] int NOT NULL IDENTITY,
    [Name] nvarchar(200) NOT NULL,
    [Enabled] bit NOT NULL,
    [Default] bit NOT NULL,
    CONSTRAINT [PK_UdapCommunities] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [UdapRootCertificates] (
    [Id] int NOT NULL IDENTITY,
    [Enabled] bit NOT NULL,
    [Name] nvarchar(max) NOT NULL,
    [X509Certificate] nvarchar(max) NOT NULL,
    [Thumbprint] nvarchar(max) NOT NULL,
    [BeginDate] datetime2 NOT NULL,
    [EndDate] datetime2 NOT NULL,
    CONSTRAINT [PK_UdapRootCertificates] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [UdapAnchors] (
    [Id] int NOT NULL IDENTITY,
    [Enabled] bit NOT NULL,
    [Name] nvarchar(max) NOT NULL,
    [X509Certificate] nvarchar(max) NOT NULL,
    [Thumbprint] nvarchar(max) NOT NULL,
    [BeginDate] datetime2 NOT NULL,
    [EndDate] datetime2 NOT NULL,
    [CommunityId] int NOT NULL,
    CONSTRAINT [PK_UdapAnchors] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_Anchor_Communities] FOREIGN KEY ([CommunityId]) REFERENCES [UdapCommunities] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [UdapCertifications] (
    [Id] int NOT NULL IDENTITY,
    [Name] nvarchar(200) NOT NULL,
    [CommunityId] int NULL,
    CONSTRAINT [PK_UdapCertifications] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_UdapCertifications_UdapCommunities_CommunityId] FOREIGN KEY ([CommunityId]) REFERENCES [UdapCommunities] ([Id])
);
GO

CREATE TABLE [UdapAnchorCertification] (
    [AnchorId] int NOT NULL,
    [CertificationId] int NOT NULL,
    CONSTRAINT [PK_UdapAnchorCertification] PRIMARY KEY ([AnchorId], [CertificationId]),
    CONSTRAINT [FK_AnchorCertification_Anchor] FOREIGN KEY ([AnchorId]) REFERENCES [UdapAnchors] ([Id]) ON DELETE CASCADE,
    CONSTRAINT [FK_AnchorCertification_Certification] FOREIGN KEY ([CertificationId]) REFERENCES [UdapCertifications] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [UdapCommunityCertification] (
    [CommunityId] int NOT NULL,
    [CertificationId] int NOT NULL,
    CONSTRAINT [PK_UdapCommunityCertification] PRIMARY KEY ([CommunityId], [CertificationId]),
    CONSTRAINT [FK_CommunityCertification_Certification] FOREIGN KEY ([CertificationId]) REFERENCES [UdapCertifications] ([Id]) ON DELETE CASCADE,
    CONSTRAINT [FK_CommunityCertification_Community] FOREIGN KEY ([CommunityId]) REFERENCES [UdapCommunities] ([Id])
);
GO

CREATE INDEX [IX_UdapAnchorCertification_CertificationId] ON [UdapAnchorCertification] ([CertificationId]);
GO

CREATE INDEX [IX_UdapAnchors_CommunityId] ON [UdapAnchors] ([CommunityId]);
GO

CREATE INDEX [IX_UdapCertifications_CommunityId] ON [UdapCertifications] ([CommunityId]);
GO

CREATE INDEX [IX_UdapCommunityCertification_CertificationId] ON [UdapCommunityCertification] ([CertificationId]);
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20230106204557_InitialSqlServerUdap', N'7.0.1');
GO

COMMIT;
GO

