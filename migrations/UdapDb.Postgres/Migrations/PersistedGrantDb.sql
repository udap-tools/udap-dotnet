﻿CREATE TABLE IF NOT EXISTS "__EFMigrationsHistory" (
    "MigrationId" character varying(150) NOT NULL,
    "ProductVersion" character varying(32) NOT NULL,
    CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY ("MigrationId")
);

START TRANSACTION;

CREATE TABLE "DeviceCodes" (
    "UserCode" character varying(200) NOT NULL,
    "DeviceCode" character varying(200) NOT NULL,
    "SubjectId" character varying(200),
    "SessionId" character varying(100),
    "ClientId" character varying(200) NOT NULL,
    "Description" character varying(200),
    "CreationTime" timestamp with time zone NOT NULL,
    "Expiration" timestamp with time zone NOT NULL,
    "Data" character varying(50000) NOT NULL,
    CONSTRAINT "PK_DeviceCodes" PRIMARY KEY ("UserCode")
);

CREATE TABLE "Keys" (
    "Id" text NOT NULL,
    "Version" integer NOT NULL,
    "Created" timestamp with time zone NOT NULL,
    "Use" text,
    "Algorithm" character varying(100) NOT NULL,
    "IsX509Certificate" boolean NOT NULL,
    "DataProtected" boolean NOT NULL,
    "Data" text NOT NULL,
    CONSTRAINT "PK_Keys" PRIMARY KEY ("Id")
);

CREATE TABLE "PersistedGrants" (
    "Id" bigint GENERATED BY DEFAULT AS IDENTITY,
    "Key" character varying(200),
    "Type" character varying(50) NOT NULL,
    "SubjectId" character varying(200),
    "SessionId" character varying(100),
    "ClientId" character varying(200) NOT NULL,
    "Description" character varying(200),
    "CreationTime" timestamp with time zone NOT NULL,
    "Expiration" timestamp with time zone,
    "ConsumedTime" timestamp with time zone,
    "Data" character varying(50000) NOT NULL,
    CONSTRAINT "PK_PersistedGrants" PRIMARY KEY ("Id")
);

CREATE TABLE "PushedAuthorizationRequests" (
    "Id" bigint GENERATED BY DEFAULT AS IDENTITY,
    "ReferenceValueHash" character varying(64) NOT NULL,
    "ExpiresAtUtc" timestamp with time zone NOT NULL,
    "Parameters" text NOT NULL,
    CONSTRAINT "PK_PushedAuthorizationRequests" PRIMARY KEY ("Id")
);

CREATE TABLE "ServerSideSessions" (
    "Id" bigint GENERATED BY DEFAULT AS IDENTITY,
    "Key" character varying(100) NOT NULL,
    "Scheme" character varying(100) NOT NULL,
    "SubjectId" character varying(100) NOT NULL,
    "SessionId" character varying(100),
    "DisplayName" character varying(100),
    "Created" timestamp with time zone NOT NULL,
    "Renewed" timestamp with time zone NOT NULL,
    "Expires" timestamp with time zone,
    "Data" text NOT NULL,
    CONSTRAINT "PK_ServerSideSessions" PRIMARY KEY ("Id")
);

CREATE UNIQUE INDEX "IX_DeviceCodes_DeviceCode" ON "DeviceCodes" ("DeviceCode");

CREATE INDEX "IX_DeviceCodes_Expiration" ON "DeviceCodes" ("Expiration");

CREATE INDEX "IX_Keys_Use" ON "Keys" ("Use");

CREATE INDEX "IX_PersistedGrants_ConsumedTime" ON "PersistedGrants" ("ConsumedTime");

CREATE INDEX "IX_PersistedGrants_Expiration" ON "PersistedGrants" ("Expiration");

CREATE UNIQUE INDEX "IX_PersistedGrants_Key" ON "PersistedGrants" ("Key");

CREATE INDEX "IX_PersistedGrants_SubjectId_ClientId_Type" ON "PersistedGrants" ("SubjectId", "ClientId", "Type");

CREATE INDEX "IX_PersistedGrants_SubjectId_SessionId_Type" ON "PersistedGrants" ("SubjectId", "SessionId", "Type");

CREATE INDEX "IX_PushedAuthorizationRequests_ExpiresAtUtc" ON "PushedAuthorizationRequests" ("ExpiresAtUtc");

CREATE UNIQUE INDEX "IX_PushedAuthorizationRequests_ReferenceValueHash" ON "PushedAuthorizationRequests" ("ReferenceValueHash");

CREATE INDEX "IX_ServerSideSessions_DisplayName" ON "ServerSideSessions" ("DisplayName");

CREATE INDEX "IX_ServerSideSessions_Expires" ON "ServerSideSessions" ("Expires");

CREATE UNIQUE INDEX "IX_ServerSideSessions_Key" ON "ServerSideSessions" ("Key");

CREATE INDEX "IX_ServerSideSessions_SessionId" ON "ServerSideSessions" ("SessionId");

CREATE INDEX "IX_ServerSideSessions_SubjectId" ON "ServerSideSessions" ("SubjectId");

INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES ('20240208170715_PersistedGrantDb_Initial', '8.0.1');

COMMIT;

