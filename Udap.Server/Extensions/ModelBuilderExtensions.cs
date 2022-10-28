#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Duende.IdentityServer.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Udap.Server.Entitiies;
using Udap.Server.Options;

namespace Udap.Server.Extensions
{
    public static class ModelBuilderExtensions
    {
        private static EntityTypeBuilder<TEntity> ToTable<TEntity>(this EntityTypeBuilder<TEntity> entityTypeBuilder, TableConfiguration configuration)
            where TEntity : class
        {
            return string.IsNullOrWhiteSpace(configuration.Schema) ? entityTypeBuilder.ToTable(configuration.Name) : entityTypeBuilder.ToTable(configuration.Name, configuration.Schema);
        }

        public static void ConfigureUdapContext(this ModelBuilder modelBuilder,
            UdapConfigurationStoreOptions storeOptions)
        {
            if (!string.IsNullOrWhiteSpace(storeOptions.DefaultSchema))
                modelBuilder.HasDefaultSchema(storeOptions.DefaultSchema);

            modelBuilder.Entity<Anchor>(anchor =>
            {
                anchor.ToTable(storeOptions.Anchor);
                anchor.HasKey(x => x.Id);

                anchor.HasOne(a => a.Community)
                    .WithMany(c => c.Anchors)
                    .IsRequired()
                    .HasForeignKey(a => a.CommunityId)
                    .HasConstraintName("FK_Anchor_Communities");

                anchor.HasMany(a => a.AnchorCertifications)
                    .WithOne(ac => ac.Anchor)
                    .IsRequired(false)
                    .HasForeignKey(ac => ac.AnchorId)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("FK_AnchorCertification_Anchor");
            });

            modelBuilder.Entity<Community>(community =>
            {
                community.ToTable(storeOptions.Community);
                community.HasKey(x => x.Id);
                community.Property(x => x.Name).HasMaxLength(200);

                community.HasMany(c => c.CommunityCertifications)
                    .WithOne(cc => cc.Community)
                    .IsRequired(false)
                    .HasForeignKey(a => a.CommunityId)
                    .HasConstraintName("FK_CommunityCertification_Community");
            });
            
            modelBuilder.Entity<Certification>(certification =>
            {
                certification.ToTable(storeOptions.Certification);
                certification.HasKey(x => x.Id);
                certification.Property(x => x.Name).HasMaxLength(200);
                
                certification.HasMany(c => c.CommunityCertifications)
                    .WithOne(cc => cc.Certification)
                    .IsRequired(false)
                    .HasForeignKey(cc => cc.CertificationId)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("FK_CommunityCertification_Certification");

                certification.HasMany(c => c.AnchorCertifications)
                    .WithOne(ac => ac.Certification)
                    .IsRequired(false)
                    .HasForeignKey(ac => ac.CertificationId)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("FK_AnchorCertification_Certification");
            });

            modelBuilder.Entity<AnchorCertification>(associate =>
            {
                associate.ToTable(storeOptions.AnchorCertificationAssociate);
                associate.HasKey(ac => new { ac.AnchorId, ac.CertificationId });
            });

            modelBuilder.Entity<CommunityCertification>(associate =>
            {
                associate.ToTable(storeOptions.CommunityCertificationAssociate);
                associate.HasKey(cc => new { cc.CommunityId, cc.CertificationId });
            });
        }
    }
}
