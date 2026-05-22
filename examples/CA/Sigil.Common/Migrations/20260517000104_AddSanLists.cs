using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddSanLists : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PresetSubjectAltNames",
                schema: "sigil",
                table: "CertificateTemplates");

            migrationBuilder.CreateTable(
                name: "SanLists",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Items = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SanLists", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CertificateTemplateSanList",
                schema: "sigil",
                columns: table => new
                {
                    SanListsId = table.Column<int>(type: "integer", nullable: false),
                    TemplatesId = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateTemplateSanList", x => new { x.SanListsId, x.TemplatesId });
                    table.ForeignKey(
                        name: "FK_CertificateTemplateSanList_CertificateTemplates_TemplatesId",
                        column: x => x.TemplatesId,
                        principalSchema: "sigil",
                        principalTable: "CertificateTemplates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CertificateTemplateSanList_SanLists_SanListsId",
                        column: x => x.SanListsId,
                        principalSchema: "sigil",
                        principalTable: "SanLists",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplateSanList_TemplatesId",
                schema: "sigil",
                table: "CertificateTemplateSanList",
                column: "TemplatesId");

            migrationBuilder.CreateIndex(
                name: "IX_SanLists_Name",
                schema: "sigil",
                table: "SanLists",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificateTemplateSanList",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "SanLists",
                schema: "sigil");

            migrationBuilder.AddColumn<string>(
                name: "PresetSubjectAltNames",
                schema: "sigil",
                table: "CertificateTemplates",
                type: "text",
                nullable: true);
        }
    }
}
