using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace UdapDb.Postgres.Migrations.ConfigurationDb
{
    /// <inheritdoc />
    public partial class ConfigurationDb_v7Tov8 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "saml_service_providers",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    entity_id = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    clock_skew_seconds = table.Column<double>(type: "double precision", nullable: true),
                    request_max_age_seconds = table.Column<double>(type: "double precision", nullable: true),
                    assertion_lifetime_seconds = table.Column<double>(type: "double precision", nullable: true),
                    require_signed_authn_requests = table.Column<bool>(type: "boolean", nullable: true),
                    require_signed_logout_responses = table.Column<bool>(type: "boolean", nullable: true),
                    allow_idp_initiated = table.Column<bool>(type: "boolean", nullable: false),
                    default_name_id_format = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    email_name_id_claim_type = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    signing_behavior = table.Column<int>(type: "integer", nullable: true),
                    allowed_signature_algorithms = table.Column<List<string>>(type: "text[]", nullable: true),
                    created = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    last_accessed = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    non_editable = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_service_providers", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "saml_allowed_scopes",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    scope = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    saml_service_provider_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_allowed_scopes", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_allowed_scopes_saml_service_providers_saml_service_provi~",
                        column: x => x.saml_service_provider_id,
                        principalSchema: "udap",
                        principalTable: "saml_service_providers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "saml_assertion_consumer_services",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    location = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: false),
                    binding = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    index = table.Column<int>(type: "integer", nullable: false),
                    is_default = table.Column<bool>(type: "boolean", nullable: false),
                    saml_service_provider_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_assertion_consumer_services", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_assertion_consumer_services_saml_service_providers_saml_~",
                        column: x => x.saml_service_provider_id,
                        principalSchema: "udap",
                        principalTable: "saml_service_providers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "saml_authn_context_mappings",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    oidc_value = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    saml_authn_context_class_ref = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    saml_service_provider_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_authn_context_mappings", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_authn_context_mappings_saml_service_providers_saml_servi~",
                        column: x => x.saml_service_provider_id,
                        principalSchema: "udap",
                        principalTable: "saml_service_providers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "saml_certificates",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    data = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: false),
                    use = table.Column<int>(type: "integer", nullable: false),
                    saml_service_provider_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_certificates", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_certificates_saml_service_providers_saml_service_provide~",
                        column: x => x.saml_service_provider_id,
                        principalSchema: "udap",
                        principalTable: "saml_service_providers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "saml_claim_mappings",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    claim_type = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    saml_attribute_name = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    saml_service_provider_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_claim_mappings", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_claim_mappings_saml_service_providers_saml_service_provi~",
                        column: x => x.saml_service_provider_id,
                        principalSchema: "udap",
                        principalTable: "saml_service_providers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "saml_requested_claim_types",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    claim_type = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    saml_service_provider_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_requested_claim_types", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_requested_claim_types_saml_service_providers_saml_servic~",
                        column: x => x.saml_service_provider_id,
                        principalSchema: "udap",
                        principalTable: "saml_service_providers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "saml_single_logout_services",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    location = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: false),
                    binding = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    saml_service_provider_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_single_logout_services", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_single_logout_services_saml_service_providers_saml_ser~",
                        column: x => x.saml_service_provider_id,
                        principalSchema: "udap",
                        principalTable: "saml_service_providers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_saml_allowed_scopes_saml_service_provider_id_scope",
                schema: "udap",
                table: "saml_allowed_scopes",
                columns: new[] { "saml_service_provider_id", "scope" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_assertion_consumer_services_saml_service_provider_id_l~",
                schema: "udap",
                table: "saml_assertion_consumer_services",
                columns: new[] { "saml_service_provider_id", "location" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_authn_context_mappings_saml_service_provider_id_oidc_v~",
                schema: "udap",
                table: "saml_authn_context_mappings",
                columns: new[] { "saml_service_provider_id", "oidc_value" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_certificates_saml_service_provider_id",
                schema: "udap",
                table: "saml_certificates",
                column: "saml_service_provider_id");

            migrationBuilder.CreateIndex(
                name: "ix_saml_claim_mappings_saml_service_provider_id_claim_type",
                schema: "udap",
                table: "saml_claim_mappings",
                columns: new[] { "saml_service_provider_id", "claim_type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_requested_claim_types_saml_service_provider_id_claim_t~",
                schema: "udap",
                table: "saml_requested_claim_types",
                columns: new[] { "saml_service_provider_id", "claim_type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_service_providers_entity_id",
                schema: "udap",
                table: "saml_service_providers",
                column: "entity_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_single_logout_services_saml_service_provider_id_binding",
                schema: "udap",
                table: "saml_single_logout_services",
                columns: new[] { "saml_service_provider_id", "binding" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "saml_allowed_scopes",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_assertion_consumer_services",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_authn_context_mappings",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_certificates",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_claim_mappings",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_requested_claim_types",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_single_logout_services",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_service_providers",
                schema: "udap");
        }
    }
}
