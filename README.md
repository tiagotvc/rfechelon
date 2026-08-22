# AccountBridge

API leve (ASP.NET Core Minimal API) que fica rodando na VPS, do lado do
banco de conta do jogo (`RF_User`, tabela `tbl_rfaccount`). É o único
jeito do site (rf-ascension, na Vercel) criar/verificar conta de jogador
usando a credencial real do jogo — sem isso, criar conta no site nunca
levaria a conseguir logar no client.

Não mexe no `AccountServer` nem no `LoginServer` existentes — projeto
totalmente separado, mesmo criptografia (Argon2id + HMAC-SHA256, copiada
de `AccountServer/Security/CryptoHelper.cs`) pra ficar compatível com o
que já está gravado no banco.

## Por que só duas rotas

- `POST /v1/accounts` — cria uma conta nova em `tbl_rfaccount`.
- `POST /v1/accounts/login` — verifica usuário/senha.

Isso é o suficiente pro fluxo "criar conta no site → logar no site →
logar no client do jogo com a mesma credencial". Não expõe nem cria nada
em `tbl_UserAccount` (isso é responsabilidade do `AccountServer` quando o
client conecta de verdade) e nunca devolve `password_hash`.

## Limite de 12 caracteres

Usuário e senha são limitados a 4–12 caracteres ASCII (sem espaço/acento)
porque é o limite do próprio protocolo do client do jogo — ver
`AccountServer/Server/LoginHandler.cs`, `LoginAccountRequest` (rejeita
id/senha com mais de 12 bytes). Criar credencial maior aqui geraria conta
que o client nunca consegue usar.

## Variáveis de ambiente (obrigatórias)

| Variável | O que é |
|---|---|
| `DATABASE_URL` | Connection string do SQL Server do banco `RF_User` (mesmo banco que o AccountServer usa) |
| `ARGON2_SALT_BASE64` | **O MESMO valor** configurado no AccountServer (Settings → Security → Argon2 Salt). Usado como salt do Argon2id e pra derivar a chave HMAC/AES-GCM — sem bater esse valor, senha criada aqui nunca verifica certo no AccountServer (e vice-versa). |
| `BRIDGE_API_KEY` | Segredo compartilhado com o site. Toda chamada em `/v1/*` precisa do header `X-Bridge-Key` com esse valor — gere algo forte, ex. `openssl rand -base64 32`. |

Sem qualquer uma dessas três, o processo recusa subir (falha rápido e
explícito, não silenciosamente).

## Rodar localmente (teste)

```bash
cd AccountBridge
DATABASE_URL="Server=...;Database=RF_User;User Id=...;Password=...;TrustServerCertificate=True" \
ARGON2_SALT_BASE64="<mesmo valor do AccountServer>" \
BRIDGE_API_KEY="uma-chave-de-teste" \
dotnet run
```

`GET /health` não exige chave, é só pra checagem de vida. Todo o resto
sob `/v1/` exige o header `X-Bridge-Key`.

## Deploy na VPS

`dotnet publish -c Release` e rodar o executável como serviço (Windows
Service via `sc create`, ou NSSM, ou Tarefa Agendada com restart — o que
já for usado pros outros servers). Coloca atrás de HTTPS de verdade
(reverse proxy — IIS/Caddy/nginx com certificado) já que o site na
Vercel vai chamar pela internet; nunca expor sem TLS.

## O que falta (não incluído de propósito)

- Rate limit básico por IP já está embutido (10 req/min em `/v1/*`), mas
  é só uma primeira camada — bloqueio de IP após N falhas seguidas
  (como o `tbl_UserAccount.LoginFailureCnt` já faz no client real) ainda
  não está aqui.
- Recuperação de senha, troca de senha, exclusão de conta — nenhuma
  rota criada ainda, só criar + logar.
- Não está no `RFOnlineServer.sln` (`dotnet build`/`dotnet run` funciona
  direto na pasta sem precisar da solution).
