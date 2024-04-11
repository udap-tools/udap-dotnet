using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace UdapDb.Postgres.Migrations.ConfigurationDb
{
    /// <inheritdoc />
    public partial class ConfigurationDB_Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "udap");

            migrationBuilder.CreateTable(
                name: "api_resources",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    allowed_access_token_signing_algorithms = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    show_in_discovery_document = table.Column<bool>(type: "boolean", nullable: false),
                    require_resource_indicator = table.Column<bool>(type: "boolean", nullable: false),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    last_accessed = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    non_editable = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_resources", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "api_scopes",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    required = table.Column<bool>(type: "boolean", nullable: false),
                    emphasize = table.Column<bool>(type: "boolean", nullable: false),
                    show_in_discovery_document = table.Column<bool>(type: "boolean", nullable: false),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    last_accessed = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    non_editable = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_scopes", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "clients",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    client_id = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    protocol_type = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    require_client_secret = table.Column<bool>(type: "boolean", nullable: false),
                    client_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    client_uri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    logo_uri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    require_consent = table.Column<bool>(type: "boolean", nullable: false),
                    allow_remember_consent = table.Column<bool>(type: "boolean", nullable: false),
                    always_include_user_claims_in_id_token = table.Column<bool>(type: "boolean", nullable: false),
                    require_pkce = table.Column<bool>(type: "boolean", nullable: false),
                    allow_plain_text_pkce = table.Column<bool>(type: "boolean", nullable: false),
                    require_request_object = table.Column<bool>(type: "boolean", nullable: false),
                    allow_access_tokens_via_browser = table.Column<bool>(type: "boolean", nullable: false),
                    require_dpo_p = table.Column<bool>(type: "boolean", nullable: false),
                    dpo_pvalidation_mode = table.Column<int>(type: "integer", nullable: false),
                    dpo_pclock_skew = table.Column<TimeSpan>(type: "interval", nullable: false),
                    front_channel_logout_uri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    front_channel_logout_session_required = table.Column<bool>(type: "boolean", nullable: false),
                    back_channel_logout_uri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    back_channel_logout_session_required = table.Column<bool>(type: "boolean", nullable: false),
                    allow_offline_access = table.Column<bool>(type: "boolean", nullable: false),
                    identity_token_lifetime = table.Column<int>(type: "integer", nullable: false),
                    allowed_identity_token_signing_algorithms = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    access_token_lifetime = table.Column<int>(type: "integer", nullable: false),
                    authorization_code_lifetime = table.Column<int>(type: "integer", nullable: false),
                    consent_lifetime = table.Column<int>(type: "integer", nullable: true),
                    absolute_refresh_token_lifetime = table.Column<int>(type: "integer", nullable: false),
                    sliding_refresh_token_lifetime = table.Column<int>(type: "integer", nullable: false),
                    refresh_token_usage = table.Column<int>(type: "integer", nullable: false),
                    update_access_token_claims_on_refresh = table.Column<bool>(type: "boolean", nullable: false),
                    refresh_token_expiration = table.Column<int>(type: "integer", nullable: false),
                    access_token_type = table.Column<int>(type: "integer", nullable: false),
                    enable_local_login = table.Column<bool>(type: "boolean", nullable: false),
                    include_jwt_id = table.Column<bool>(type: "boolean", nullable: false),
                    always_send_client_claims = table.Column<bool>(type: "boolean", nullable: false),
                    client_claims_prefix = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    pair_wise_subject_salt = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    initiate_login_uri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    user_sso_lifetime = table.Column<int>(type: "integer", nullable: true),
                    user_code_type = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    device_code_lifetime = table.Column<int>(type: "integer", nullable: false),
                    ciba_lifetime = table.Column<int>(type: "integer", nullable: true),
                    polling_interval = table.Column<int>(type: "integer", nullable: true),
                    coordinate_lifetime_with_user_session = table.Column<bool>(type: "boolean", nullable: true),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    last_accessed = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    non_editable = table.Column<bool>(type: "boolean", nullable: false),
                    pushed_authorization_lifetime = table.Column<int>(type: "integer", nullable: true),
                    require_pushed_authorization = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_clients", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "identity_providers",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    scheme = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    type = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    properties = table.Column<string>(type: "text", nullable: true),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    last_accessed = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    non_editable = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_providers", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "identity_resources",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    required = table.Column<bool>(type: "boolean", nullable: false),
                    emphasize = table.Column<bool>(type: "boolean", nullable: false),
                    show_in_discovery_document = table.Column<bool>(type: "boolean", nullable: false),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    non_editable = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_resources", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "api_resource_claims",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    api_resource_id = table.Column<int>(type: "integer", nullable: false),
                    type = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_resource_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_api_resource_claims_api_resources_api_resource_id",
                        column: x => x.api_resource_id,
                        principalSchema: "udap",
                        principalTable: "api_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "api_resource_properties",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    api_resource_id = table.Column<int>(type: "integer", nullable: false),
                    key = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    value = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_resource_properties", x => x.id);
                    table.ForeignKey(
                        name: "fk_api_resource_properties_api_resources_api_resource_id",
                        column: x => x.api_resource_id,
                        principalSchema: "udap",
                        principalTable: "api_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "api_resource_scopes",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    scope = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    api_resource_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_resource_scopes", x => x.id);
                    table.ForeignKey(
                        name: "fk_api_resource_scopes_api_resources_api_resource_id",
                        column: x => x.api_resource_id,
                        principalSchema: "udap",
                        principalTable: "api_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "api_resource_secrets",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    api_resource_id = table.Column<int>(type: "integer", nullable: false),
                    description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    value = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: false),
                    expiration = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    type = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_resource_secrets", x => x.id);
                    table.ForeignKey(
                        name: "fk_api_resource_secrets_api_resources_api_resource_id",
                        column: x => x.api_resource_id,
                        principalSchema: "udap",
                        principalTable: "api_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "api_scope_claims",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    scope_id = table.Column<int>(type: "integer", nullable: false),
                    type = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_scope_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_api_scope_claims_api_scopes_scope_id",
                        column: x => x.scope_id,
                        principalSchema: "udap",
                        principalTable: "api_scopes",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "api_scope_properties",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    scope_id = table.Column<int>(type: "integer", nullable: false),
                    key = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    value = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_api_scope_properties", x => x.id);
                    table.ForeignKey(
                        name: "fk_api_scope_properties_api_scopes_scope_id",
                        column: x => x.scope_id,
                        principalSchema: "udap",
                        principalTable: "api_scopes",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_claims",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    type = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    value = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    client_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_claims_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_cors_origins",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    origin = table.Column<string>(type: "character varying(150)", maxLength: 150, nullable: false),
                    client_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_cors_origins", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_cors_origins_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_grant_types",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    grant_type = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    client_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_grant_types", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_grant_types_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_id_prestrictions",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    provider = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    client_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_id_prestrictions", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_id_prestrictions_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_post_logout_redirect_uris",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    post_logout_redirect_uri = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: false),
                    client_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_post_logout_redirect_uris", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_post_logout_redirect_uris_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_properties",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    client_id = table.Column<int>(type: "integer", nullable: false),
                    key = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    value = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_properties", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_properties_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_redirect_uris",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    redirect_uri = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: false),
                    client_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_redirect_uris", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_redirect_uris_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_scopes",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    scope = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    client_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_scopes", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_scopes_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "client_secrets",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    client_id = table.Column<int>(type: "integer", nullable: false),
                    description = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    value = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: false),
                    expiration = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    type = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_secrets", x => x.id);
                    table.ForeignKey(
                        name: "fk_client_secrets_clients_client_id",
                        column: x => x.client_id,
                        principalSchema: "udap",
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "identity_resource_claims",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    identity_resource_id = table.Column<int>(type: "integer", nullable: false),
                    type = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_resource_claims", x => x.id);
                    table.ForeignKey(
                        name: "fk_identity_resource_claims_identity_resources_identity_resour~",
                        column: x => x.identity_resource_id,
                        principalSchema: "udap",
                        principalTable: "identity_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "identity_resource_properties",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    identity_resource_id = table.Column<int>(type: "integer", nullable: false),
                    key = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    value = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_resource_properties", x => x.id);
                    table.ForeignKey(
                        name: "fk_identity_resource_properties_identity_resources_identity_re~",
                        column: x => x.identity_resource_id,
                        principalSchema: "udap",
                        principalTable: "identity_resources",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_api_resource_claims_api_resource_id_type",
                schema: "udap",
                table: "api_resource_claims",
                columns: new[] { "api_resource_id", "type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_api_resource_properties_api_resource_id_key",
                schema: "udap",
                table: "api_resource_properties",
                columns: new[] { "api_resource_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_api_resource_scopes_api_resource_id_scope",
                schema: "udap",
                table: "api_resource_scopes",
                columns: new[] { "api_resource_id", "scope" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_api_resource_secrets_api_resource_id",
                schema: "udap",
                table: "api_resource_secrets",
                column: "api_resource_id");

            migrationBuilder.CreateIndex(
                name: "ix_api_resources_name",
                schema: "udap",
                table: "api_resources",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_api_scope_claims_scope_id_type",
                schema: "udap",
                table: "api_scope_claims",
                columns: new[] { "scope_id", "type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_api_scope_properties_scope_id_key",
                schema: "udap",
                table: "api_scope_properties",
                columns: new[] { "scope_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_api_scopes_name",
                schema: "udap",
                table: "api_scopes",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_claims_client_id_type_value",
                schema: "udap",
                table: "client_claims",
                columns: new[] { "client_id", "type", "value" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_cors_origins_client_id_origin",
                schema: "udap",
                table: "client_cors_origins",
                columns: new[] { "client_id", "origin" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_grant_types_client_id_grant_type",
                schema: "udap",
                table: "client_grant_types",
                columns: new[] { "client_id", "grant_type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_id_prestrictions_client_id_provider",
                schema: "udap",
                table: "client_id_prestrictions",
                columns: new[] { "client_id", "provider" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_post_logout_redirect_uris_client_id_post_logout_redi~",
                schema: "udap",
                table: "client_post_logout_redirect_uris",
                columns: new[] { "client_id", "post_logout_redirect_uri" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_properties_client_id_key",
                schema: "udap",
                table: "client_properties",
                columns: new[] { "client_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_redirect_uris_client_id_redirect_uri",
                schema: "udap",
                table: "client_redirect_uris",
                columns: new[] { "client_id", "redirect_uri" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_scopes_client_id_scope",
                schema: "udap",
                table: "client_scopes",
                columns: new[] { "client_id", "scope" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_client_secrets_client_id",
                schema: "udap",
                table: "client_secrets",
                column: "client_id");

            migrationBuilder.CreateIndex(
                name: "ix_clients_client_id",
                schema: "udap",
                table: "clients",
                column: "client_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_identity_providers_scheme",
                schema: "udap",
                table: "identity_providers",
                column: "scheme",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_identity_resource_claims_identity_resource_id_type",
                schema: "udap",
                table: "identity_resource_claims",
                columns: new[] { "identity_resource_id", "type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_identity_resource_properties_identity_resource_id_key",
                schema: "udap",
                table: "identity_resource_properties",
                columns: new[] { "identity_resource_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_identity_resources_name",
                schema: "udap",
                table: "identity_resources",
                column: "name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "api_resource_claims",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "api_resource_properties",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "api_resource_scopes",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "api_resource_secrets",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "api_scope_claims",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "api_scope_properties",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_claims",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_cors_origins",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_grant_types",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_id_prestrictions",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_post_logout_redirect_uris",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_properties",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_redirect_uris",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_scopes",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "client_secrets",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "identity_providers",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "identity_resource_claims",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "identity_resource_properties",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "api_resources",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "api_scopes",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "clients",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "identity_resources",
                schema: "udap");
        }
    }
}
