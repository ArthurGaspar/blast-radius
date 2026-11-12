using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace BlastRadius.Api.Data;

/// <summary>Migrations target PostgreSQL; SQLite (local runs, tests) is created from the model directly.</summary>
public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<AppDb>
{
    public AppDb CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<AppDb>().UseNpgsql("Host=localhost;Database=blast_radius;Username=postgres").Options);
}
