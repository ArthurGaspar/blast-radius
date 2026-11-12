using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using BlastRadius.Api.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace BlastRadius.Api.Http;

public sealed class JwtOptions
{
    public string Secret { get; set; } = "";
    public string Issuer { get; set; } = "blast-radius";
    public double Hours { get; set; } = 12;

    public SymmetricSecurityKey Key()
    {
        var bytes = Encoding.UTF8.GetBytes(Secret);
        if (bytes.Length < 32) throw new InvalidOperationException("Jwt:Secret must be at least 32 bytes");
        return new SymmetricSecurityKey(bytes);
    }
}

public static partial class AuthEndpoints
{
    public sealed record RegisterRequest(string? Username, string? DisplayName, string? Password);
    public sealed record LoginRequest(string? Username, string? Password);
    public sealed record UserView(Guid Id, string Username, string DisplayName);
    public sealed record AuthResponse(string Token, UserView User);

    [GeneratedRegex("^[A-Za-z0-9_]{3,32}$")]
    private static partial Regex UsernamePattern();

    private static readonly PasswordHasher<User> Hasher = new();

    public static void Map(WebApplication app)
    {
        var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");

        auth.MapPost("/register", async (RegisterRequest req, AppDb db, IOptions<JwtOptions> jwt, TimeProvider time, CancellationToken ct) =>
        {
            var errors = new List<string>();
            if (req.Username == null || !UsernamePattern().IsMatch(req.Username)) errors.Add("username must be 3-32 letters, digits or _");
            if (string.IsNullOrWhiteSpace(req.DisplayName) || req.DisplayName.Trim().Length > 60) errors.Add("displayName must be 1-60 characters");
            if (req.Password == null || req.Password.Length < 10 || req.Password.Length > 128) errors.Add("password must be 10-128 characters");
            if (errors.Count > 0) throw ApiError.Invalid(string.Join("; ", errors));
            var lower = req.Username!.ToLowerInvariant();
            if (await db.Users.AnyAsync(u => u.Username.ToLower() == lower, ct))
                throw ApiError.Conflict("auth.username-taken", "That username is already registered");

            var user = new User { Username = req.Username!, DisplayName = req.DisplayName!.Trim(), CreatedAt = time.GetUtcNow() };
            user.PasswordHash = Hasher.HashPassword(user, req.Password!);
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
            return Results.Created("/api/me", Issue(user, jwt.Value, time));
        });

        auth.MapPost("/login", async (LoginRequest req, AppDb db, IOptions<JwtOptions> jwt, TimeProvider time, CancellationToken ct) =>
        {
            var lower = (req.Username ?? "").ToLowerInvariant();
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username.ToLower() == lower, ct);
            // hash even when the user doesn't exist, so response time doesn't reveal which usernames are taken
            var verified = user != null
                ? Hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password ?? "")
                : Hasher.VerifyHashedPassword(Dummy, DummyHash, req.Password ?? "");
            if (user == null || verified == PasswordVerificationResult.Failed)
                throw new ApiError(401, "auth.bad-credentials", "Username or password is wrong");
            return Results.Ok(Issue(user, jwt.Value, time));
        });

        app.MapGet("/api/me", async (ClaimsPrincipal principal, AppDb db, CancellationToken ct) =>
        {
            var id = principal.UserId();
            var user = await db.Users.FindAsync([id], ct) ?? throw new ApiError(401, "auth.unknown-user", "This account no longer exists");
            return new
            {
                user = new UserView(user.Id, user.Username, user.DisplayName),
                sites = await db.Sites.CountAsync(s => s.UserId == id, ct),
                assets = await db.Assets.CountAsync(a => a.UserId == id, ct),
                unread = await db.Notifications.CountAsync(n => n.UserId == id && n.ReadAt == null, ct),
            };
        }).RequireAuthorization();
    }

    private static readonly User Dummy = new() { Username = "dummy", DisplayName = "dummy" };
    private static readonly string DummyHash = Hasher.HashPassword(Dummy, Guid.NewGuid().ToString());

    public static AuthResponse Issue(User user, JwtOptions o, TimeProvider time)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var token = new JwtSecurityToken(
            issuer: o.Issuer, audience: o.Issuer,
            claims: [new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), new Claim("name", user.Username)],
            notBefore: now, expires: now.AddHours(o.Hours),
            signingCredentials: new SigningCredentials(o.Key(), SecurityAlgorithms.HmacSha256));
        return new AuthResponse(new JwtSecurityTokenHandler().WriteToken(token), new UserView(user.Id, user.Username, user.DisplayName));
    }
}
