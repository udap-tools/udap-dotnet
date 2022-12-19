using Microsoft.AspNetCore.Hosting.StaticWebAssets;
using Microsoft.EntityFrameworkCore;
using MudBlazor.Services;
using Udap.CA.DbContexts;
using Udap.CA.Services;
using Udap.CA.Services.State;

var builder = WebApplication.CreateBuilder(args);

StaticWebAssetsLoader.UseStaticWebAssets(builder.Environment, builder.Configuration);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddMudServices();
builder.Services.AddAutoMapper(typeof(Program));


builder.Services.AddDbContext<IUdapCaContext, UdapCaContext>( //todo: maybe implement as store pattern with IUdapCaContext, later to accomodate view only kinds of interactions...
    options => options.UseSqlite(connectionString)
        .LogTo(Console.WriteLine, LogLevel.Information));

builder.Services.AddSingleton<CommunityState>();
builder.Services.AddScoped<CommunityService>();
builder.Services.AddScoped<RootCertificateService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();