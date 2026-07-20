using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace UdapDb.Postgres.Migrations.PersistedGrantDb
{
    /// <inheritdoc />
    public partial class PersistedGrantDb_v7Tov8 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "saml_logout_sessions",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    logout_id = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    serialized_session = table.Column<string>(type: "text", nullable: false),
                    expires_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_logout_sessions", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "saml_signin_states",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    state_id = table.Column<Guid>(type: "uuid", nullable: false),
                    serialized_state = table.Column<string>(type: "text", nullable: false),
                    expires_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    service_provider_entity_id = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_signin_states", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "saml_logout_session_request_indices",
                schema: "udap",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    request_id = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    saml_logout_session_id = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_saml_logout_session_request_indices", x => x.id);
                    table.ForeignKey(
                        name: "fk_saml_logout_session_request_indices_saml_logout_sessions_sa~",
                        column: x => x.saml_logout_session_id,
                        principalSchema: "udap",
                        principalTable: "saml_logout_sessions",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_saml_logout_session_request_indices_request_id",
                schema: "udap",
                table: "saml_logout_session_request_indices",
                column: "request_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_logout_session_request_indices_saml_logout_session_id",
                schema: "udap",
                table: "saml_logout_session_request_indices",
                column: "saml_logout_session_id");

            migrationBuilder.CreateIndex(
                name: "ix_saml_logout_sessions_expires_at_utc",
                schema: "udap",
                table: "saml_logout_sessions",
                column: "expires_at_utc");

            migrationBuilder.CreateIndex(
                name: "ix_saml_logout_sessions_logout_id",
                schema: "udap",
                table: "saml_logout_sessions",
                column: "logout_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_saml_signin_states_expires_at_utc",
                schema: "udap",
                table: "saml_signin_states",
                column: "expires_at_utc");

            migrationBuilder.CreateIndex(
                name: "ix_saml_signin_states_state_id",
                schema: "udap",
                table: "saml_signin_states",
                column: "state_id",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "saml_logout_session_request_indices",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_signin_states",
                schema: "udap");

            migrationBuilder.DropTable(
                name: "saml_logout_sessions",
                schema: "udap");
        }
    }
}
