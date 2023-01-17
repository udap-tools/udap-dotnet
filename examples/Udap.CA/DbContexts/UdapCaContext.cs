using Microsoft.EntityFrameworkCore;
using Udap.CA.Entities;

namespace Udap.CA.DbContexts;

public interface IUdapCaContext : IDisposable
{
    DbSet<Community> Communities { get; set; }
    DbSet<RootCertificate> RootCertificates { get; set; }
    DbSet<Anchor> Anchors { get; set; }
    DbSet<IssuedCertificate> IssuedCertificates { get; set; }
    // DbSet<Certification> Certifications { get; set; }
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public class UdapCaContext : DbContext, IUdapCaContext
{
    public UdapCaContext(DbContextOptions options) : base(options)
    {
        this.Database.EnsureCreated();
    }
    
    public DbSet<Community> Communities { get; set; }
    public DbSet<RootCertificate> RootCertificates { get; set; }
    public DbSet<Anchor> Anchors { get; set; }
    public DbSet<IssuedCertificate> IssuedCertificates { get; set; }
    // public DbSet<Certification> Certifications { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Community>(community =>
        {
            community.ToTable(name: "Communities"); //, table => table.IsTemporal());  // Not for SQLite :(
            community.HasKey(e => e.Id);

            community.Property(x => x.Name).HasMaxLength(200);
            
            community.HasMany(c => c.RootCertificates)
                .WithOne(r => r.Community)
                .IsRequired(false)
                .HasForeignKey(r => r.CommunityId)
                .HasConstraintName("FK_RootCertificates_Community");
        });

        modelBuilder.Entity<RootCertificate>(rootCert =>
        {
            rootCert.ToTable("RootCertificates");
            rootCert.HasKey(e => e.Id);

            rootCert.HasMany(r => r.Anchors)
                .WithOne(a => a.RootCertificate)
                .IsRequired(false)
                .HasForeignKey(a => a.RootCertificateId)
                .HasConstraintName("FK_Anchors_RootCertificate");
        });

        modelBuilder.Entity<Anchor>(anchor =>
        {
            anchor.ToTable("Anchors");
            anchor.HasKey(e => e.Id);

            anchor.HasMany(r => r.IssuedCertificates)
                .WithOne(a => a.Anchor)
                .IsRequired(false)
                .HasForeignKey(a => a.AnchorId)
                .HasConstraintName("FK_IssuedCertificates_Anchor");
        });

        // modelBuilder.Entity<Certification>(certification =>
        // {
        //     certification.ToTable("Certifications");
        //     certification.HasKey(e => e.Id);
        // });

        modelBuilder.Entity<IssuedCertificate>(issuedCert =>
        {
            issuedCert.ToTable("IssuedCertificates");
            issuedCert.HasKey(e => e.Id);
        });
    }
}
