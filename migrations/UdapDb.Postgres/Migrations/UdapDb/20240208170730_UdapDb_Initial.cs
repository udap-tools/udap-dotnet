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
            migrationBuilder.CreateTable(
                name: "DataProtectionKeys",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    FriendlyName = table.Column<string>(type: "text", nullable: true),
                    Xml = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DataProtectionKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TieredClients",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    ClientName = table.Column<string>(type: "text", nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false),
                    IdPBaseUrl = table.Column<string>(type: "text", nullable: false),
                    RedirectUri = table.Column<string>(type: "text", nullable: false),
                    ClientUriSan = table.Column<string>(type: "text", nullable: false),
                    CommunityId = table.Column<int>(type: "integer", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    TokenEndpoint = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TieredClients", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UdapCommunities",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Default = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UdapCommunities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UdapAnchors",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    X509Certificate = table.Column<string>(type: "text", nullable: false),
                    Thumbprint = table.Column<string>(type: "text", nullable: false),
                    BeginDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    EndDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CommunityId = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UdapAnchors", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Anchor_Communities",
                        column: x => x.CommunityId,
                        principalTable: "UdapCommunities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UdapCertifications",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CommunityId = table.Column<int>(type: "integer", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UdapCertifications", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UdapCertifications_UdapCommunities_CommunityId",
                        column: x => x.CommunityId,
                        principalTable: "UdapCommunities",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "UdapIntermediateCertificates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    AnchorId = table.Column<int>(type: "integer", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    X509Certificate = table.Column<string>(type: "text", nullable: false),
                    Thumbprint = table.Column<string>(type: "text", nullable: false),
                    BeginDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    EndDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UdapIntermediateCertificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IntermediateCertificate_Anchor",
                        column: x => x.AnchorId,
                        principalTable: "UdapAnchors",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UdapAnchorCertification",
                columns: table => new
                {
                    AnchorId = table.Column<int>(type: "integer", nullable: false),
                    CertificationId = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UdapAnchorCertification", x => new { x.AnchorId, x.CertificationId });
                    table.ForeignKey(
                        name: "FK_AnchorCertification_Anchor",
                        column: x => x.AnchorId,
                        principalTable: "UdapAnchors",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AnchorCertification_Certification",
                        column: x => x.CertificationId,
                        principalTable: "UdapCertifications",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UdapCommunityCertification",
                columns: table => new
                {
                    CommunityId = table.Column<int>(type: "integer", nullable: false),
                    CertificationId = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UdapCommunityCertification", x => new { x.CommunityId, x.CertificationId });
                    table.ForeignKey(
                        name: "FK_CommunityCertification_Certification",
                        column: x => x.CertificationId,
                        principalTable: "UdapCertifications",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CommunityCertification_Community",
                        column: x => x.CommunityId,
                        principalTable: "UdapCommunities",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_UdapAnchorCertification_CertificationId",
                table: "UdapAnchorCertification",
                column: "CertificationId");

            migrationBuilder.CreateIndex(
                name: "IX_UdapAnchors_CommunityId",
                table: "UdapAnchors",
                column: "CommunityId");

            migrationBuilder.CreateIndex(
                name: "IX_UdapCertifications_CommunityId",
                table: "UdapCertifications",
                column: "CommunityId");

            migrationBuilder.CreateIndex(
                name: "IX_UdapCommunityCertification_CertificationId",
                table: "UdapCommunityCertification",
                column: "CertificationId");

            migrationBuilder.CreateIndex(
                name: "IX_UdapIntermediateCertificates_AnchorId",
                table: "UdapIntermediateCertificates",
                column: "AnchorId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DataProtectionKeys");

            migrationBuilder.DropTable(
                name: "TieredClients");

            migrationBuilder.DropTable(
                name: "UdapAnchorCertification");

            migrationBuilder.DropTable(
                name: "UdapCommunityCertification");

            migrationBuilder.DropTable(
                name: "UdapIntermediateCertificates");

            migrationBuilder.DropTable(
                name: "UdapCertifications");

            migrationBuilder.DropTable(
                name: "UdapAnchors");

            migrationBuilder.DropTable(
                name: "UdapCommunities");
        }
    }
}
