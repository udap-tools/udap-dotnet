#nullable disable

using Microsoft.EntityFrameworkCore.Migrations;

namespace Udap.Server.Migrations.UdapDb
{
    public partial class Udap : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UdapCommunities",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    Default = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UdapCommunities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UdapAnchors",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    X509Certificate = table.Column<string>(type: "TEXT", nullable: false),
                    Thumbprint = table.Column<string>(type: "TEXT", nullable: false),
                    BeginDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    EndDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CommunityId = table.Column<long>(type: "INTEGER", nullable: false)
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
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CommunityId = table.Column<long>(type: "INTEGER", nullable: true)
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
                name: "UdapAnchorCertification",
                columns: table => new
                {
                    AnchorId = table.Column<long>(type: "INTEGER", nullable: false),
                    CertificationId = table.Column<long>(type: "INTEGER", nullable: false)
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
                    CommunityId = table.Column<long>(type: "INTEGER", nullable: false),
                    CertificationId = table.Column<long>(type: "INTEGER", nullable: false)
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
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UdapAnchorCertification");

            migrationBuilder.DropTable(
                name: "UdapCommunityCertification");

            migrationBuilder.DropTable(
                name: "UdapAnchors");

            migrationBuilder.DropTable(
                name: "UdapCertifications");

            migrationBuilder.DropTable(
                name: "UdapCommunities");
        }
    }
}
