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
// Base BILLING (Cash real, tbl_UserStatus) — mesma instância/credencial das outras duas na maioria
// dos setups, só trocando o Database=. Só leitura aqui (crédito continua indo pelo WorldServer/
// g_RFAcc.CreditBalance — isso aqui é só pra MOSTRAR o saldo real na tela, nunca escrevemos direto).
var billingDatabaseUrl = RequireEnv("BILLING_DATABASE_URL");
var argon2SaltBase64 = RequireEnv("ARGON2_SALT_BASE64");
var bridgeApiKey = RequireEnv("BRIDGE_API_KEY");
// Onde o mod side-channel do WorldServer escuta — por padrão localhost, já que este bridge roda
// na mesma VPS. Só precisa mudar se o WorldServer estiver em outra máquina da mesma rede.
var worldServerHost = Environment.GetEnvironmentVariable("WORLDSERVER_STATUS_HOST") ?? "127.0.0.1";
var worldServerPort = int.TryParse(Environment.GetEnvironmentVariable("WORLDSERVER_STATUS_PORT"), out var parsedPort) ? parsedPort : 27601;
// Canal separado (Fase 2 da loja de doações) que CONCEDE ITEM — porta e segredo
// próprios, distintos do canal de status acima (que é só leitura, sem auth).
var deliveryHost = Environment.GetEnvironmentVariable("WORLDSERVER_DELIVERY_HOST") ?? worldServerHost;
var deliveryPort = int.TryParse(Environment.GetEnvironmentVariable("WORLDSERVER_DELIVERY_PORT"), out var parsedDeliveryPort) ? parsedDeliveryPort : 27602;
var deliverySecret = RequireEnv("WORLDSERVER_DELIVERY_SECRET");

var hmacKey = Convert.FromBase64String(argon2SaltBase64);
var argon2Salt = hmacKey; // mesmo valor, mesma logica do AccountServer (AccountDatabaseEf._hmacKey)

builder.Services.AddDbContext<BridgeDbContext>(options =>
    options.UseSqlServer(databaseUrl));
builder.Services.AddDbContext<WorldDbContext>(options =>
    options.UseSqlServer(worldDatabaseUrl));
builder.Services.AddDbContext<BillingDbContext>(options =>
    options.UseSqlServer(billingDatabaseUrl));

// Esse limiter e' uma rede de seguranca contra a PROPRIA bridge broncar (loop,
// bug, chave vazada) - NAO e' a defesa real contra brute-force de senha. O
// motivo: todo request aqui vem do backend do site (Vercel), nunca direto do
// navegador do jogador - um unico bucket global (era PermitLimit=10, sem
// particionar por chamador) achatava TODO mundo junto (registro, login,
// listar personagem, entregar pacote) e ja quebraria com poucos jogadores
// navegando /gamecp ao mesmo tempo (cada carregamento de pagina chama
// /v1/characters). A defesa real contra tentativa de senha em massa mora no
// site (rate limit por IP real do visitante, ver app/lib/rate-limit.ts no
// repo rf-ascension) - so' o site enxerga o IP de quem esta' de fato pedindo.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("auth", limiterOptions =>
    {
        limiterOptions.PermitLimit = 300;
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
    if (!TryValidateNewCredentials(request.Username, request.Password, out var error))
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
    if (!TryValidateExistingCredentials(request.Username, request.Password, out var error))
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
// tbl_rfaccount). So leitura, nunca escreve em tbl_base/tbl_supplement.
// dalant/goldPoint agora tambem voltam aqui (Fase 5, aba Recarregar) —
// join manual em vez de FK de verdade porque tbl_supplement nao tem uma
// declarada, so' compartilha Serial com tbl_base.
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
        .Select(c => new { serial = c.Serial, name = c.Name, level = c.Lv, race = c.Race, dalant = c.Dalant })
        .ToListAsync();

    if (characters.Count == 0)
    {
        return Results.Ok(characters.Select(c => new { c.serial, c.name, c.level, c.race, c.dalant, goldPoint = 0 }));
    }

    var serials = characters.Select(c => c.serial).ToList();
    var goldPoints = await world.Supplements
        .AsNoTracking()
        .Where(s => serials.Contains(s.Serial))
        .ToDictionaryAsync(s => s.Serial, s => s.ActionPoint_2);

    var result = characters.Select(c => new
    {
        c.serial,
        c.name,
        c.level,
        c.race,
        c.dalant,
        goldPoint = goldPoints.GetValueOrDefault(c.serial, 0),
    });

    return Results.Ok(result);
}).RequireRateLimiting("auth");

// Saldo real de Cash (base BILLING, tbl_UserStatus) — so' leitura, pra mostrar na tela. Cash e' por
// CONTA (nao por personagem), diferente de Dalant/Gold Point.
v1.MapGet("/cash", async (string? username, BillingDbContext billing) =>
{
    if (!IsValidUsername(username, out var error))
    {
        return Results.BadRequest(new { error });
    }

    var row = await billing.UserStatus.AsNoTracking().FirstOrDefaultAsync(u => u.Id == username);
    return Results.Ok(new { cash = row?.Cash ?? 0 });
}).RequireRateLimiting("auth");

// Troca Game CP (site) por moeda real do jogo (Fase 5) — repassa pro opcode 5/6 do
// CStoreDeliveryChannel. Mesma regra de nunca lançar erro de conexão pra fora.
v1.MapPost("/exchange", async (ExchangeRequest request) =>
{
    if (!IsValidUsername(request.AccountUsername, out var usernameError) || request.Amount == 0)
    {
        return Results.BadRequest(new { error = "accountUsername válido e amount > 0 são obrigatórios." });
    }
    var currency = request.Currency?.ToLowerInvariant();
    if (currency != "cash" && currency != "dalant" && currency != "goldpoint")
    {
        return Results.BadRequest(new { error = "currency precisa ser cash, dalant ou goldpoint." });
    }
    if (currency != "cash" && request.CharacterSerial == 0)
    {
        return Results.BadRequest(new { error = "characterSerial é obrigatório pra trocar Dalant/Gold Point." });
    }

    var currencyType = currency switch
    {
        "cash" => StoreDeliveryClient.CurrencyType.Cash,
        "dalant" => StoreDeliveryClient.CurrencyType.Dalant,
        _ => StoreDeliveryClient.CurrencyType.GoldPoint,
    };

    var ok = await StoreDeliveryClient.CreditCurrencyAsync(
        deliveryHost,
        deliveryPort,
        deliverySecret,
        request.CharacterSerial,
        request.AccountUsername,
        currencyType,
        request.Amount,
        TimeSpan.FromSeconds(8));

    return Results.Ok(new { ok });
}).RequireRateLimiting("auth");

// Entrega de verdade no personagem (Fase 2 da loja de doações) — repassa
// pro canal novo do WorldServer (CStoreDeliveryChannel, StoreDeliveryClient.cs).
// Nunca lança pra fora um erro de conexão: devolve {ok:false} pro site
// decidir se tenta de novo depois (fila `deliveries`, status='queued').
v1.MapPost("/deliver", async (DeliverRequest request) =>
{
    if (request.CharacterSerial == 0 || string.IsNullOrWhiteSpace(request.ItemCode) || request.Amount == 0)
    {
        return Results.BadRequest(new { error = "characterSerial, itemCode e amount são obrigatórios." });
    }

    var result = await StoreDeliveryClient.DeliverAsync(
        deliveryHost,
        deliveryPort,
        deliverySecret,
        request.CharacterSerial,
        request.ItemCode,
        request.Amount,
        TimeSpan.FromSeconds(8));

    if (!result.Ok)
    {
        var status = result.Status == StoreDeliveryClient.DeliveryStatus.NotFound ? "not_found" : "error";
        return Results.Ok(new { ok = false, status });
    }

    return Results.Ok(new { ok = true, status = result.Status == StoreDeliveryClient.DeliveryStatus.Bag ? "bag" : "mail" });
}).RequireRateLimiting("auth");

// Entrega de pacote completo (Fase 3 — vários itens + Cash real numa call só). accountUsername é a
// conta já autenticada no site (a bridge não descobre dono do personagem, o site já sabe). Mesma
// regra de nunca lançar erro de conexão pra fora — {ok:false} pro site decidir se tenta de novo.
v1.MapPost("/deliver-package", async (DeliverPackageRequest request) =>
{
    if (request.CharacterSerial == 0 || !IsValidUsername(request.AccountUsername, out var usernameError)
        || request.Items is null || request.Items.Count == 0 || request.Items.Count > 255)
    {
        return Results.BadRequest(new { error = "characterSerial, accountUsername válido e ao menos 1 item são obrigatórios." });
    }
    if (request.Items.Any(i => string.IsNullOrWhiteSpace(i.ItemCode) || i.Amount == 0))
    {
        return Results.BadRequest(new { error = "Todo item precisa de itemCode e amount > 0." });
    }

    var items = request.Items
        .Select(i => new StoreDeliveryClient.PackageItem(i.ItemCode, i.Amount))
        .ToList();

    var result = await StoreDeliveryClient.DeliverPackageAsync(
        deliveryHost,
        deliveryPort,
        deliverySecret,
        request.CharacterSerial,
        request.AccountUsername,
        request.CashAmount,
        items,
        TimeSpan.FromSeconds(8));

    var cashStatus = result.CashStatus switch
    {
        StoreDeliveryClient.CashCreditStatus.Credited => "credited",
        StoreDeliveryClient.CashCreditStatus.Skipped => "skipped",
        _ => "error",
    };
    var itemStatuses = result.ItemStatuses
        .Select(st => st switch
        {
            StoreDeliveryClient.DeliveryStatus.Bag => "bag",
            StoreDeliveryClient.DeliveryStatus.Mail => "mail",
            _ => "error",
        })
        .ToList();

    return Results.Ok(new { ok = result.Ok, cashStatus, itemStatuses });
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

// Mínimo de 4 só faz sentido pra conta NOVA (UX de cadastro) — o protocolo real do client só
// rejeita acima de 12 chars (LoginHandler.LoginAccountRequest, AccountServer:263/268), sem mínimo
// nenhum. Contas de GM pré-existentes têm 3 caracteres (ex.: "gm3") e são válidas de verdade.
static bool TryValidateNewCredentials(string? username, string? password, out string error)
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

// Login de conta JÁ EXISTENTE — não pode exigir o mínimo de 4 (ver comentário acima), só o teto
// real de 12 do protocolo.
static bool TryValidateExistingCredentials(string? username, string? password, out string error)
{
    if (string.IsNullOrWhiteSpace(username) || username.Length > 12 || !IsAscii(username))
    {
        error = "Usuário inválido.";
        return false;
    }
    if (string.IsNullOrWhiteSpace(password) || password.Length > 12 || !IsAscii(password))
    {
        error = "Senha inválida.";
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

// Usado pelas rotas que operam sobre uma conta JÁ EXISTENTE (characters/cash/exchange/deliver-
// package) — mesma regra do login, sem mínimo de 4.
static bool IsValidUsername(string? username, out string error)
{
    if (string.IsNullOrWhiteSpace(username) || username.Length > 12 || !IsAscii(username))
    {
        error = "Usuário inválido.";
        return false;
    }
    error = "";
    return true;
}

public sealed record AccountRequest(string Username, string Password);

public sealed record DeliverRequest(uint CharacterSerial, string ItemCode, uint Amount);

public sealed record DeliverPackageItem(string ItemCode, uint Amount);

public sealed record DeliverPackageRequest(uint CharacterSerial, string AccountUsername, int CashAmount, List<DeliverPackageItem> Items);

public sealed record ExchangeRequest(uint CharacterSerial, string AccountUsername, string Currency, uint Amount);

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
    public int Dalant { get; set; }
}

// tbl_supplement.ActionPoint_2 = Gold Point (slots 0/1 sao Mining/Hunting Point, nao confundir —
// ver pesquisa de reverse engineering desta sessao). So' leitura aqui, credito passa pelo WorldServer.
public sealed class SupplementRow
{
    public int Serial { get; set; }
    public int ActionPoint_2 { get; set; }
}

public sealed class WorldDbContext(DbContextOptions<WorldDbContext> options) : DbContext(options)
{
    public DbSet<CharacterRow> Characters => Set<CharacterRow>();
    public DbSet<SupplementRow> Supplements => Set<SupplementRow>();

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
            entity.Property(e => e.Dalant).HasColumnName("Dalant");
        });
        modelBuilder.Entity<SupplementRow>(entity =>
        {
            entity.ToTable("tbl_supplement", "dbo");
            entity.HasKey(e => e.Serial);
            entity.Property(e => e.Serial).HasColumnName("Serial");
            entity.Property(e => e.ActionPoint_2).HasColumnName("ActionPoint_2");
        });
    }
}

// Base BILLING (Cash real), so' leitura. Mesma tabela que g_RFAcc.CreditBalance (WorldServer)
// escreve — nunca escrevemos aqui, so' consultamos pra exibir o saldo real na tela.
public sealed class UserStatusRow
{
    public string Id { get; set; } = "";
    public int Cash { get; set; }
}

public sealed class BillingDbContext(DbContextOptions<BillingDbContext> options) : DbContext(options)
{
    public DbSet<UserStatusRow> UserStatus => Set<UserStatusRow>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserStatusRow>(entity =>
        {
            entity.ToTable("tbl_UserStatus", "dbo");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("ID");
            entity.Property(e => e.Cash).HasColumnName("Cash");
        });
    }
}
