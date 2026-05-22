using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class RenameCommunityToTrustDomain : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Drop foreign keys first — table/column renames can't happen while FKs reference them.
            migrationBuilder.DropForeignKey(
                name: "FK_CaCertificates_Communities_CommunityId",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropForeignKey(
                name: "FK_CommunityBaseUrls_Communities_CommunityId",
                schema: "sigil",
                table: "CommunityBaseUrls");

            // Rename FK columns
            migrationBuilder.RenameColumn(
                name: "CommunityId",
                schema: "sigil",
                table: "CaCertificates",
                newName: "TrustDomainId");

            migrationBuilder.RenameColumn(
                name: "CommunityId",
                schema: "sigil",
                table: "CommunityBaseUrls",
                newName: "TrustDomainId");

            // Rename tables
            migrationBuilder.RenameTable(
                name: "Communities",
                schema: "sigil",
                newName: "TrustDomains");

            migrationBuilder.RenameTable(
                name: "CommunityBaseUrls",
                schema: "sigil",
                newName: "TrustDomainBaseUrls");

            // Rename indexes
            migrationBuilder.RenameIndex(
                name: "IX_CaCertificates_CommunityId",
                schema: "sigil",
                table: "CaCertificates",
                newName: "IX_CaCertificates_TrustDomainId");

            migrationBuilder.RenameIndex(
                name: "IX_Communities_Name",
                schema: "sigil",
                table: "TrustDomains",
                newName: "IX_TrustDomains_Name");

            migrationBuilder.RenameIndex(
                name: "IX_CommunityBaseUrls_CommunityId_SortOrder",
                schema: "sigil",
                table: "TrustDomainBaseUrls",
                newName: "IX_TrustDomainBaseUrls_TrustDomainId_SortOrder");

            // Rename primary key constraints (no EF helper — raw SQL)
            migrationBuilder.Sql(@"ALTER TABLE sigil.""TrustDomains"" RENAME CONSTRAINT ""PK_Communities"" TO ""PK_TrustDomains""");
            migrationBuilder.Sql(@"ALTER TABLE sigil.""TrustDomainBaseUrls"" RENAME CONSTRAINT ""PK_CommunityBaseUrls"" TO ""PK_TrustDomainBaseUrls""");

            // Re-create foreign keys with new names referencing renamed tables
            migrationBuilder.AddForeignKey(
                name: "FK_CaCertificates_TrustDomains_TrustDomainId",
                schema: "sigil",
                table: "CaCertificates",
                column: "TrustDomainId",
                principalSchema: "sigil",
                principalTable: "TrustDomains",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_TrustDomainBaseUrls_TrustDomains_TrustDomainId",
                schema: "sigil",
                table: "TrustDomainBaseUrls",
                column: "TrustDomainId",
                principalSchema: "sigil",
                principalTable: "TrustDomains",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CaCertificates_TrustDomains_TrustDomainId",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropForeignKey(
                name: "FK_TrustDomainBaseUrls_TrustDomains_TrustDomainId",
                schema: "sigil",
                table: "TrustDomainBaseUrls");

            migrationBuilder.Sql(@"ALTER TABLE sigil.""TrustDomains"" RENAME CONSTRAINT ""PK_TrustDomains"" TO ""PK_Communities""");
            migrationBuilder.Sql(@"ALTER TABLE sigil.""TrustDomainBaseUrls"" RENAME CONSTRAINT ""PK_TrustDomainBaseUrls"" TO ""PK_CommunityBaseUrls""");

            migrationBuilder.RenameIndex(
                name: "IX_TrustDomainBaseUrls_TrustDomainId_SortOrder",
                schema: "sigil",
                table: "TrustDomainBaseUrls",
                newName: "IX_CommunityBaseUrls_CommunityId_SortOrder");

            migrationBuilder.RenameIndex(
                name: "IX_TrustDomains_Name",
                schema: "sigil",
                table: "TrustDomains",
                newName: "IX_Communities_Name");

            migrationBuilder.RenameIndex(
                name: "IX_CaCertificates_TrustDomainId",
                schema: "sigil",
                table: "CaCertificates",
                newName: "IX_CaCertificates_CommunityId");

            migrationBuilder.RenameTable(
                name: "TrustDomainBaseUrls",
                schema: "sigil",
                newName: "CommunityBaseUrls");

            migrationBuilder.RenameTable(
                name: "TrustDomains",
                schema: "sigil",
                newName: "Communities");

            migrationBuilder.RenameColumn(
                name: "TrustDomainId",
                schema: "sigil",
                table: "CommunityBaseUrls",
                newName: "CommunityId");

            migrationBuilder.RenameColumn(
                name: "TrustDomainId",
                schema: "sigil",
                table: "CaCertificates",
                newName: "CommunityId");

            migrationBuilder.AddForeignKey(
                name: "FK_CaCertificates_Communities_CommunityId",
                schema: "sigil",
                table: "CaCertificates",
                column: "CommunityId",
                principalSchema: "sigil",
                principalTable: "Communities",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_CommunityBaseUrls_Communities_CommunityId",
                schema: "sigil",
                table: "CommunityBaseUrls",
                column: "CommunityId",
                principalSchema: "sigil",
                principalTable: "Communities",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
