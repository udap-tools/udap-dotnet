﻿IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
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

CREATE TABLE [DeviceCodes] (
    [UserCode] nvarchar(200) NOT NULL,
    [DeviceCode] nvarchar(200) NOT NULL,
    [SubjectId] nvarchar(200) NULL,
    [SessionId] nvarchar(100) NULL,
    [ClientId] nvarchar(200) NOT NULL,
    [Description] nvarchar(200) NULL,
    [CreationTime] datetime2 NOT NULL,
    [Expiration] datetime2 NOT NULL,
    [Data] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_DeviceCodes] PRIMARY KEY ([UserCode])
);
GO

CREATE TABLE [Keys] (
    [Id] nvarchar(450) NOT NULL,
    [Version] int NOT NULL,
    [Created] datetime2 NOT NULL,
    [Use] nvarchar(450) NULL,
    [Algorithm] nvarchar(100) NOT NULL,
    [IsX509Certificate] bit NOT NULL,
    [DataProtected] bit NOT NULL,
    [Data] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_Keys] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [PersistedGrants] (
    [Id] bigint NOT NULL IDENTITY,
    [Key] nvarchar(200) NULL,
    [Type] nvarchar(50) NOT NULL,
    [SubjectId] nvarchar(200) NULL,
    [SessionId] nvarchar(100) NULL,
    [ClientId] nvarchar(200) NOT NULL,
    [Description] nvarchar(200) NULL,
    [CreationTime] datetime2 NOT NULL,
    [Expiration] datetime2 NULL,
    [ConsumedTime] datetime2 NULL,
    [Data] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_PersistedGrants] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [ServerSideSessions] (
    [Id] int NOT NULL IDENTITY,
    [Key] nvarchar(100) NOT NULL,
    [Scheme] nvarchar(100) NOT NULL,
    [SubjectId] nvarchar(100) NOT NULL,
    [SessionId] nvarchar(100) NULL,
    [DisplayName] nvarchar(100) NULL,
    [Created] datetime2 NOT NULL,
    [Renewed] datetime2 NOT NULL,
    [Expires] datetime2 NULL,
    [Data] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_ServerSideSessions] PRIMARY KEY ([Id])
);
GO

CREATE UNIQUE INDEX [IX_DeviceCodes_DeviceCode] ON [DeviceCodes] ([DeviceCode]);
GO

CREATE INDEX [IX_DeviceCodes_Expiration] ON [DeviceCodes] ([Expiration]);
GO

CREATE INDEX [IX_Keys_Use] ON [Keys] ([Use]);
GO

CREATE INDEX [IX_PersistedGrants_ConsumedTime] ON [PersistedGrants] ([ConsumedTime]);
GO

CREATE INDEX [IX_PersistedGrants_Expiration] ON [PersistedGrants] ([Expiration]);
GO

CREATE UNIQUE INDEX [IX_PersistedGrants_Key] ON [PersistedGrants] ([Key]) WHERE [Key] IS NOT NULL;
GO

CREATE INDEX [IX_PersistedGrants_SubjectId_ClientId_Type] ON [PersistedGrants] ([SubjectId], [ClientId], [Type]);
GO

CREATE INDEX [IX_PersistedGrants_SubjectId_SessionId_Type] ON [PersistedGrants] ([SubjectId], [SessionId], [Type]);
GO

CREATE INDEX [IX_ServerSideSessions_DisplayName] ON [ServerSideSessions] ([DisplayName]);
GO

CREATE INDEX [IX_ServerSideSessions_Expires] ON [ServerSideSessions] ([Expires]);
GO

CREATE UNIQUE INDEX [IX_ServerSideSessions_Key] ON [ServerSideSessions] ([Key]);
GO

CREATE INDEX [IX_ServerSideSessions_SessionId] ON [ServerSideSessions] ([SessionId]);
GO

CREATE INDEX [IX_ServerSideSessions_SubjectId] ON [ServerSideSessions] ([SubjectId]);
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20230410170347_Grants', N'8.0.1');
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

ALTER TABLE [ServerSideSessions] DROP CONSTRAINT [PK_ServerSideSessions];
GO

DECLARE @var0 sysname;
SELECT @var0 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ServerSideSessions]') AND [c].[name] = N'Id');
IF @var0 IS NOT NULL EXEC(N'ALTER TABLE [ServerSideSessions] DROP CONSTRAINT [' + @var0 + '];');
ALTER TABLE [ServerSideSessions] ALTER COLUMN [Id] bigint NOT NULL;
GO

ALTER TABLE [ServerSideSessions] ADD CONSTRAINT [PK_ServerSideSessions] PRIMARY KEY ([Id]);
GO

CREATE TABLE [PushedAuthorizationRequests] (
    [Id] bigint NOT NULL IDENTITY,
    [ReferenceValueHash] nvarchar(64) NOT NULL,
    [ExpiresAtUtc] datetime2 NOT NULL,
    [Parameters] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_PushedAuthorizationRequests] PRIMARY KEY ([Id])
);
GO

CREATE INDEX [IX_PushedAuthorizationRequests_ExpiresAtUtc] ON [PushedAuthorizationRequests] ([ExpiresAtUtc]);
GO

CREATE UNIQUE INDEX [IX_PushedAuthorizationRequests_ReferenceValueHash] ON [PushedAuthorizationRequests] ([ReferenceValueHash]);
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20240131171824_PersistedGrantDb__v6Tov7', N'8.0.1');
GO

COMMIT;
GO

