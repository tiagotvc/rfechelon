using System.Text;
using System.Threading.RateLimiting;
using AccountBridge;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

// API leve, separada do AccountServer/LoginServer existentes (nao mexe
// neles). So fala com tbl_rfaccount (a tabela de credencial real do jogo,
// ver AccountServer/scheme/RF_User_mssql.sql) usando a MESMA criptografia
// (Argon2id + HMAC-SHA256, ver CryptoHelper.cs) pra ficar compativel com o
// que o AccountServer ja grava/le. O site (rf-ascension) e o unico cliente
// esperado — protegido por uma chave compartilhada (BRIDGE_API_KEY).
//
// Variaveis de ambiente obrigatorias:
//   DATABASE_URL        connection string do SQL Server da conta (RF_User)
//   ARGON2_SALT_BASE64   MESMO valor configurado no AccountServer (Settings
//                        > Security > Argon2SaltBase64) — usado como salt
//                        do Argon2id e pra derivar a chave HMAC/AES. Sem
//                        isso, senha criada aqui nunca bate com o que o
//                        AccountServer calcularia (e vice-versa).
//   BRIDGE_API_KEY       segredo compartilhado com o site; toda chamada
//                        precisa do header X-Bridge-Key com esse valor.
//   WORLD_DATABASE_URL   connection string do SQL Server de personagens
//                        (RF_World) — mesma instancia/credencial do
//                        DATABASE_URL acima, so trocando o banco (Database=)
//                        na maioria dos setups. Usada por GET /v1/characters
//                        (le tbl_base, nunca escreve nada la).
//
// Limite de 12 caracteres em usuario/senha: vem do proprio protocolo do
// cliente do jogo (ver AccountServer/Server/LoginHandler.cs,
// LoginAccountRequest — rejeita id/senha com mais de 12 chars). Criar
// conta com usuario/senha maior aqui geraria uma conta que o cliente do
// jogo nunca consegue de fato logar.

var builder = WebApplication.CreateBuilder(args);

var databaseUrl = RequireEnv("DATABASE_URL");
var worldDatabaseUrl = RequireEnv("WORLD_DATABASE_URL");
var argon2SaltBase64 = RequireEnv("ARGON2_SALT_BASE64");
var bridgeApiKey = RequireEnv("BRIDGE_API_KEY");
// Onde o mod side-channel do WorldServer escuta — por padrão localhost, já que este bridge roda
// na mesma VPS. Só precisa mudar se o WorldServer estiver em outra máquina da mesma rede.
var worldServerHost = Environment.GetEnvironmentVariable("WORLDSERVER_STATUS_HOST") ?? "127.0.0.1";
var worldServerPort = int.TryParse(Environment.GetEnvironmentVariable("WORLDSERVER_STATUS_PORT"), out var parsedPort) ? parsedPort : 27601;

var hmacKey = Convert.FromBase64String(argon2SaltBase64);
var argon2Salt = hmacKey; // mesmo valor, mesma logica do AccountServer (AccountDatabaseEf._hmacKey)

builder.Services.AddDbContext<BridgeDbContext>(options =>
    options.UseSqlServer(databaseUrl));
builder.Services.AddDbContext<WorldDbContext>(options =>
    options.UseSqlServer(worldDatabaseUrl));

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("auth", limiterOptions =>
    {
        limiterOptions.PermitLimit = 10;
        limiterOptions.Window = TimeSpan.FromMinutes(1);
        limiterOptions.QueueLimit = 0;
    });
});

var app = builder.Build();
app.UseRateLimiter();

app.MapGet("/health", () => Results.Ok(new { ok = true }));

var v1 = app.MapGroup("/v1").AddEndpointFilter(async (context, next) =>
{
    if (!context.HttpContext.Request.Headers.TryGetValue("X-Bridge-Key", out var provided) ||
        !CryptographicEquals(provided.ToString(), bridgeApiKey))
    {
        return Results.Unauthorized();
    }
    return await next(context);
});

v1.MapPost("/accounts", async (AccountRequest request, BridgeDbContext db) =>
{
    if (!TryValidateCredentials(request.Username, request.Password, out var error))
    {
        return Results.BadRequest(new { error });
    }

    var idHmac = CryptoHelper.ComputeHmacSha256(Encoding.UTF8.GetBytes(request.Username), hmacKey);
    var exists = await db.Accounts.AsNoTracking().AnyAsync(a => a.IdHmac == idHmac);
    if (exists)
    {
        return Results.Conflict(new { error = "Esse nome de usuário já está em uso." });
    }

    var aesKey = System.Security.Cryptography.SHA256.HashData(hmacKey);
    var idEnc = CryptoHelper.EncryptAesGcm(aesKey, Encoding.UTF8.GetBytes(request.Username));
    var passwordHash = Convert.ToBase64String(CryptoHelper.HashArgon2id(Encoding.UTF8.GetBytes(request.Password), argon2Salt));

    db.Accounts.Add(new AccountAuth
    {
        IdHmac = idHmac,
        IdEnc = idEnc,
        PasswordHash = passwordHash,
        AccountType = 0,
    });
    await db.SaveChangesAsync();

    return Results.Created($"/v1/accounts/{Convert.ToHexString(idHmac)}", new { ok = true });
}).RequireRateLimiting("auth");

v1.MapPost("/accounts/login", async (AccountRequest request, BridgeDbContext db) =>
{
    if (!TryValidateCredentials(request.Username, request.Password, out var error))
    {
        return Results.BadRequest(new { error });
    }

    var idHmac = CryptoHelper.ComputeHmacSha256(Encoding.UTF8.GetBytes(request.Username), hmacKey);
    var account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.IdHmac == idHmac);
    if (account is null)
    {
        return Results.Json(new { ok = false, error = "Usuário ou senha inválidos." }, statusCode: StatusCodes.Status401Unauthorized);
    }

    var expected = Convert.FromBase64String(account.PasswordHash);
    var ok = CryptoHelper.VerifyArgon2id(Encoding.UTF8.GetBytes(request.Password), argon2Salt, expected);
    if (!ok)
    {
        return Results.Json(new { ok = false, error = "Usuário ou senha inválidos." }, statusCode: StatusCodes.Status401Unauthorized);
    }

    return Results.Ok(new { ok = true, username = request.Username });
}).RequireRateLimiting("auth");

v1.MapGet("/status", async () =>
{
    var status = await WorldServerStatusClient.GetStatusAsync(worldServerHost, worldServerPort, TimeSpan.FromSeconds(4));
    return Results.Ok(new { online = status.Online, playersOnline = status.PlayersOnline });
});

// Lista os personagens de uma conta (tbl_base.Account = usuario em texto
// puro, o mesmo digitado no login — nao precisa reverter o HMAC de
// tbl_rfaccount). So leitura, nunca escreve em tbl_base.
v1.MapGet("/characters", async (string? username, WorldDbContext world) =>
{
    if (!IsValidUsername(username, out var error))
    {
        return Results.BadRequest(new { error });
    }

    var characters = await world.Characters
        .AsNoTracking()
        .Where(c => c.Account == username)
        .OrderBy(c => c.Slot)
        .Select(c => new { serial = c.Serial, name = c.Name, level = c.Lv, race = c.Race })
        .ToListAsync();

    return Results.Ok(characters);
}).RequireRateLimiting("auth");

app.Run();

static string RequireEnv(string name)
{
    var value = Environment.GetEnvironmentVariable(name);
    if (string.IsNullOrWhiteSpace(value))
    {
        throw new InvalidOperationException($"Variável de ambiente obrigatória ausente: {name}");
    }
    return value;
}

static bool CryptographicEquals(string a, string b)
{
    var bytesA = Encoding.UTF8.GetBytes(a);
    var bytesB = Encoding.UTF8.GetBytes(b);
    return bytesA.Length == bytesB.Length && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
}

// Mesmo limite de 12 caracteres do protocolo do cliente do jogo — ver
// LoginHandler.LoginAccountRequest (AccountServer). ASCII simples, sem
// espaço, pra bater com PacketStringUtil.ToAsciiNullTerm.
static bool TryValidateCredentials(string? username, string? password, out string error)
{
    if (string.IsNullOrWhiteSpace(username) || username.Length < 4 || username.Length > 12 || !IsAscii(username))
    {
        error = "Usuário deve ter de 4 a 12 caracteres (letras e números, sem espaço ou acento).";
        return false;
    }
    if (string.IsNullOrWhiteSpace(password) || password.Length < 4 || password.Length > 12 || !IsAscii(password))
    {
        error = "Senha deve ter de 4 a 12 caracteres (letras e números, sem espaço ou acento).";
        return false;
    }
    error = "";
    return true;
}

static bool IsAscii(string value)
{
    foreach (var c in value)
    {
        if (c > 127 || char.IsWhiteSpace(c)) return false;
    }
    return true;
}

static bool IsValidUsername(string? username, out string error)
{
    if (string.IsNullOrWhiteSpace(username) || username.Length < 4 || username.Length > 12 || !IsAscii(username))
    {
        error = "Usuário deve ter de 4 a 12 caracteres (letras e números, sem espaço ou acento).";
        return false;
    }
    error = "";
    return true;
}

public sealed record AccountRequest(string Username, string Password);

public sealed class AccountAuth
{
    public byte[] IdHmac { get; set; } = [];
    public byte[] IdEnc { get; set; } = [];
    public string PasswordHash { get; set; } = "";
    public byte AccountType { get; set; }
    public DateTime? BirthDate { get; set; }
}

public sealed class BridgeDbContext(DbContextOptions<BridgeDbContext> options) : DbContext(options)
{
    public DbSet<AccountAuth> Accounts => Set<AccountAuth>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AccountAuth>(entity =>
        {
            entity.ToTable("tbl_rfaccount", "dbo");
            entity.HasKey(e => e.IdHmac);
            entity.Property(e => e.IdHmac).HasColumnName("id_hmac").HasColumnType("binary(32)");
            entity.Property(e => e.IdEnc).HasColumnName("id_enc");
            entity.Property(e => e.PasswordHash).HasColumnName("password_hash").HasMaxLength(255);
            entity.Property(e => e.AccountType).HasColumnName("accounttype");
            entity.Property(e => e.BirthDate).HasColumnName("birthdate");
        });
    }
}

// Personagem (avatar) — tbl_base no banco RF_World. Só os campos que a
// loja de doações precisa pra deixar o jogador escolher o personagem;
// nunca escreve nada nessa tabela (inventário/entrega é tarefa da Fase 2).
public sealed class CharacterRow
{
    public int Serial { get; set; }
    public string Name { get; set; } = "";
    public string Account { get; set; } = "";
    public int Slot { get; set; }
    public int Race { get; set; }
    public int Lv { get; set; }
}

public sealed class WorldDbContext(DbContextOptions<WorldDbContext> options) : DbContext(options)
{
    public DbSet<CharacterRow> Characters => Set<CharacterRow>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<CharacterRow>(entity =>
        {
            entity.ToTable("tbl_base", "dbo");
            entity.HasKey(e => e.Serial);
            entity.Property(e => e.Serial).HasColumnName("Serial");
            entity.Property(e => e.Name).HasColumnName("Name").HasMaxLength(17);
            entity.Property(e => e.Account).HasColumnName("Account").HasMaxLength(17);
            entity.Property(e => e.Slot).HasColumnName("Slot");
            entity.Property(e => e.Race).HasColumnName("Race");
            entity.Property(e => e.Lv).HasColumnName("Lv");
        });
    }
}
