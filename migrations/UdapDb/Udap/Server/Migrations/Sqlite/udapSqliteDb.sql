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

BEGIN TRANSACTION;
GO

DECLARE @var0 sysname;
SELECT @var0 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapRootCertificates]') AND [c].[name] = N'X509Certificate');
IF @var0 IS NOT NULL EXEC(N'ALTER TABLE [UdapRootCertificates] DROP CONSTRAINT [' + @var0 + '];');
ALTER TABLE [UdapRootCertificates] ALTER COLUMN [X509Certificate] TEXT NOT NULL;
GO

DECLARE @var1 sysname;
SELECT @var1 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapRootCertificates]') AND [c].[name] = N'Thumbprint');
IF @var1 IS NOT NULL EXEC(N'ALTER TABLE [UdapRootCertificates] DROP CONSTRAINT [' + @var1 + '];');
ALTER TABLE [UdapRootCertificates] ALTER COLUMN [Thumbprint] TEXT NOT NULL;
GO

DECLARE @var2 sysname;
SELECT @var2 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapRootCertificates]') AND [c].[name] = N'Name');
IF @var2 IS NOT NULL EXEC(N'ALTER TABLE [UdapRootCertificates] DROP CONSTRAINT [' + @var2 + '];');
ALTER TABLE [UdapRootCertificates] ALTER COLUMN [Name] TEXT NOT NULL;
GO

DECLARE @var3 sysname;
SELECT @var3 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapRootCertificates]') AND [c].[name] = N'EndDate');
IF @var3 IS NOT NULL EXEC(N'ALTER TABLE [UdapRootCertificates] DROP CONSTRAINT [' + @var3 + '];');
ALTER TABLE [UdapRootCertificates] ALTER COLUMN [EndDate] TEXT NOT NULL;
GO

DECLARE @var4 sysname;
SELECT @var4 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapRootCertificates]') AND [c].[name] = N'Enabled');
IF @var4 IS NOT NULL EXEC(N'ALTER TABLE [UdapRootCertificates] DROP CONSTRAINT [' + @var4 + '];');
ALTER TABLE [UdapRootCertificates] ALTER COLUMN [Enabled] INTEGER NOT NULL;
GO

DECLARE @var5 sysname;
SELECT @var5 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapRootCertificates]') AND [c].[name] = N'BeginDate');
IF @var5 IS NOT NULL EXEC(N'ALTER TABLE [UdapRootCertificates] DROP CONSTRAINT [' + @var5 + '];');
ALTER TABLE [UdapRootCertificates] ALTER COLUMN [BeginDate] TEXT NOT NULL;
GO

DECLARE @var6 sysname;
SELECT @var6 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapRootCertificates]') AND [c].[name] = N'Id');
IF @var6 IS NOT NULL EXEC(N'ALTER TABLE [UdapRootCertificates] DROP CONSTRAINT [' + @var6 + '];');
ALTER TABLE [UdapRootCertificates] ALTER COLUMN [Id] INTEGER NOT NULL;
GO

DROP INDEX [IX_UdapCommunityCertification_CertificationId] ON [UdapCommunityCertification];
DECLARE @var7 sysname;
SELECT @var7 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCommunityCertification]') AND [c].[name] = N'CertificationId');
IF @var7 IS NOT NULL EXEC(N'ALTER TABLE [UdapCommunityCertification] DROP CONSTRAINT [' + @var7 + '];');
ALTER TABLE [UdapCommunityCertification] ALTER COLUMN [CertificationId] INTEGER NOT NULL;
CREATE INDEX [IX_UdapCommunityCertification_CertificationId] ON [UdapCommunityCertification] ([CertificationId]);
GO

DECLARE @var8 sysname;
SELECT @var8 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCommunityCertification]') AND [c].[name] = N'CommunityId');
IF @var8 IS NOT NULL EXEC(N'ALTER TABLE [UdapCommunityCertification] DROP CONSTRAINT [' + @var8 + '];');
ALTER TABLE [UdapCommunityCertification] ALTER COLUMN [CommunityId] INTEGER NOT NULL;
GO

DECLARE @var9 sysname;
SELECT @var9 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCommunities]') AND [c].[name] = N'Name');
IF @var9 IS NOT NULL EXEC(N'ALTER TABLE [UdapCommunities] DROP CONSTRAINT [' + @var9 + '];');
ALTER TABLE [UdapCommunities] ALTER COLUMN [Name] TEXT NOT NULL;
GO

DECLARE @var10 sysname;
SELECT @var10 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCommunities]') AND [c].[name] = N'Enabled');
IF @var10 IS NOT NULL EXEC(N'ALTER TABLE [UdapCommunities] DROP CONSTRAINT [' + @var10 + '];');
ALTER TABLE [UdapCommunities] ALTER COLUMN [Enabled] INTEGER NOT NULL;
GO

DECLARE @var11 sysname;
SELECT @var11 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCommunities]') AND [c].[name] = N'Default');
IF @var11 IS NOT NULL EXEC(N'ALTER TABLE [UdapCommunities] DROP CONSTRAINT [' + @var11 + '];');
ALTER TABLE [UdapCommunities] ALTER COLUMN [Default] INTEGER NOT NULL;
GO

DECLARE @var12 sysname;
SELECT @var12 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCommunities]') AND [c].[name] = N'Id');
IF @var12 IS NOT NULL EXEC(N'ALTER TABLE [UdapCommunities] DROP CONSTRAINT [' + @var12 + '];');
ALTER TABLE [UdapCommunities] ALTER COLUMN [Id] INTEGER NOT NULL;
GO

DECLARE @var13 sysname;
SELECT @var13 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCertifications]') AND [c].[name] = N'Name');
IF @var13 IS NOT NULL EXEC(N'ALTER TABLE [UdapCertifications] DROP CONSTRAINT [' + @var13 + '];');
ALTER TABLE [UdapCertifications] ALTER COLUMN [Name] TEXT NOT NULL;
GO

DROP INDEX [IX_UdapCertifications_CommunityId] ON [UdapCertifications];
DECLARE @var14 sysname;
SELECT @var14 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCertifications]') AND [c].[name] = N'CommunityId');
IF @var14 IS NOT NULL EXEC(N'ALTER TABLE [UdapCertifications] DROP CONSTRAINT [' + @var14 + '];');
ALTER TABLE [UdapCertifications] ALTER COLUMN [CommunityId] INTEGER NULL;
CREATE INDEX [IX_UdapCertifications_CommunityId] ON [UdapCertifications] ([CommunityId]);
GO

DECLARE @var15 sysname;
SELECT @var15 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapCertifications]') AND [c].[name] = N'Id');
IF @var15 IS NOT NULL EXEC(N'ALTER TABLE [UdapCertifications] DROP CONSTRAINT [' + @var15 + '];');
ALTER TABLE [UdapCertifications] ALTER COLUMN [Id] INTEGER NOT NULL;
GO

DECLARE @var16 sysname;
SELECT @var16 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'X509Certificate');
IF @var16 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var16 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [X509Certificate] TEXT NOT NULL;
GO

DECLARE @var17 sysname;
SELECT @var17 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'Thumbprint');
IF @var17 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var17 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [Thumbprint] TEXT NOT NULL;
GO

DECLARE @var18 sysname;
SELECT @var18 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'Name');
IF @var18 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var18 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [Name] TEXT NOT NULL;
GO

DECLARE @var19 sysname;
SELECT @var19 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'EndDate');
IF @var19 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var19 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [EndDate] TEXT NOT NULL;
GO

DECLARE @var20 sysname;
SELECT @var20 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'Enabled');
IF @var20 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var20 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [Enabled] INTEGER NOT NULL;
GO

DROP INDEX [IX_UdapAnchors_CommunityId] ON [UdapAnchors];
DECLARE @var21 sysname;
SELECT @var21 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'CommunityId');
IF @var21 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var21 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [CommunityId] INTEGER NOT NULL;
CREATE INDEX [IX_UdapAnchors_CommunityId] ON [UdapAnchors] ([CommunityId]);
GO

DECLARE @var22 sysname;
SELECT @var22 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'BeginDate');
IF @var22 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var22 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [BeginDate] TEXT NOT NULL;
GO

DECLARE @var23 sysname;
SELECT @var23 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchors]') AND [c].[name] = N'Id');
IF @var23 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchors] DROP CONSTRAINT [' + @var23 + '];');
ALTER TABLE [UdapAnchors] ALTER COLUMN [Id] INTEGER NOT NULL;
GO

DROP INDEX [IX_UdapAnchorCertification_CertificationId] ON [UdapAnchorCertification];
DECLARE @var24 sysname;
SELECT @var24 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchorCertification]') AND [c].[name] = N'CertificationId');
IF @var24 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchorCertification] DROP CONSTRAINT [' + @var24 + '];');
ALTER TABLE [UdapAnchorCertification] ALTER COLUMN [CertificationId] INTEGER NOT NULL;
CREATE INDEX [IX_UdapAnchorCertification_CertificationId] ON [UdapAnchorCertification] ([CertificationId]);
GO

DECLARE @var25 sysname;
SELECT @var25 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[UdapAnchorCertification]') AND [c].[name] = N'AnchorId');
IF @var25 IS NOT NULL EXEC(N'ALTER TABLE [UdapAnchorCertification] DROP CONSTRAINT [' + @var25 + '];');
ALTER TABLE [UdapAnchorCertification] ALTER COLUMN [AnchorId] INTEGER NOT NULL;
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20230106204611_InitialSqliteUdap', N'7.0.1');
GO

COMMIT;
GO

