using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace UdapDb.Postgres.Migrations.UdapDb
{
    /// <inheritdoc />
    public partial class UdapDb_Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "udap");

            migrationBuilder.CreateTable(
                name: "data_protection_keys",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    friendly_name = table.Column<string>(type: "text", nullable: true),
                    xml = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_data_protection_keys", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "tiered_clients",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    client_name = table.Column<string>(type: "text", nullable: false),
                    client_id = table.Column<string>(type: "text", nullable: false),
                    id_pbase_url = table.Column<string>(type: "text", nullable: false),
                    redirect_uri = table.Column<string>(type: "text", nullable: false),
                    client_uri_san = table.Column<string>(type: "text", nullable: false),
                    community_id = table.Column<int>(type: "integer", nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    token_endpoint = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_tiered_clients", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "udap_communities",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    @default = table.Column<bool>(name: "default", type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_udap_communities", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "udap_anchors",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    x509_certificate = table.Column<string>(type: "text", nullable: false),
                    thumbprint = table.Column<string>(type: "text", nullable: false),
                    begin_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    end_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    community_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_udap_anchors", x => x.id);
                    table.ForeignKey(
                        name: "fk_anchor_communities",
                        column: x => x.community_id,
                        principalSchema: "udap",
                        principalTable: "udap_communities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "udap_certifications",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    community_id = table.Column<int>(type: "integer", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_udap_certifications", x => x.id);
                    table.ForeignKey(
                        name: "fk_udap_certifications_udap_communities_community_id",
                        column: x => x.community_id,
                        principalSchema: "udap",
                        principalTable: "udap_communities",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "udap_intermediate_certificates",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    anchor_id = table.Column<int>(type: "integer", nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    name = table.Column<string>(type: "text", nullable: false),
                    x509_certificate = table.Column<string>(type: "text", nullable: false),
                    thumbprint = table.Column<string>(type: "text", nullable: false),
                    begin_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    end_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_udap_intermediate_certificates", x => x.id);
                    table.ForeignKey(
                        name: "fk_intermediate_certificate_anchor",
                        column: x => x.anchor_id,
                        principalSchema: "udap",
                        principalTable: "udap_anchors",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "udap_anchor_certification",
                schema: "udap",
                columns: table => new
                {
                    anchor_id = table.Column<int>(type: "integer", nullable: false),
                    certification_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_udap_anchor_certification", x => new { x.anchor_id, x.certification_id });
                    table.ForeignKey(
                        name: "fk_anchor_certification_anchor",
                        column: x => x.anchor_id,
                        principalSchema: "udap",
                        principalTable: "udap_anchors",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_anchor_certification_certification",
                        column: x => x.certification_id,
                        principalSchema: "udap",
                        principalTable: "udap_certifications",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "udap_community_certification",
                schema: "udap",
                columns: table => new
                {
                    community_id = table.Column<int>(type: "integer", nullable: false),
                    certification_id = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_udap_community_certification", x => new { x.community_id, x.certification_id });
                    table.ForeignKey(
                        name: "fk_community_certification_certification",
                        column: x => x.certification_id,
                        principalSchema: "udap",
                        principalTable: "udap_certifications",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_community_certification_community",
                        column: x => x.community_id,
                        principalSchema: "udap",
                        principalTable: "udap_communities",
                        principalColumn: "id");
                });

            migrationBuilder.CreateIndex(
                name: "ix_udap_anchor_certification_certification_id",
                schema: "udap",
                table: "udap_anchor_certification",
                column: "certification_id");

            migrationBuilder.CreateIndex(
                name: "ix_udap_anchors_community_id",
                schema: "udap",
                table: "udap_anchors",
                column: "community_id");

            migrationBuilder.CreateIndex(
                name: "ix_udap_certifications_community_id",
                schema: "udap",
                table: "udap_certifications",
                column: "community_id");

            migrationBuilder.CreateIndex(
                name: "ix_udap_community_certification_certification_id",
                schema: "udap",
                table: "udap_community_certification",
                column: "certification_id");

            migrationBuilder.CreateIndex(
                name: "ix_udap_intermediate_certificates_anchor_id",
                schema: "udap",
                table: "udap_intermediate_certificates",
                column: "anchor_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "data_protection_keys",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "tiered_clients",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "udap_anchor_certification",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "udap_community_certification",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "udap_intermediate_certificates",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "udap_certifications",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "udap_anchors",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "udap_communities",
                schema: "udap");
        }
    }
}
