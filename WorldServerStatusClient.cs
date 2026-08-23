using System.Net.Sockets;

namespace AccountBridge;

// Mesmo protocolo que o launcher já usa (RFLauncher/Services/ServerStatusClient.cs) pra falar
// com o mod side-channel do WorldServer (porta 27601 por padrão — ver WorldServer.cpp /
// CModSideChannel.cpp, MSG_GET_SERVER_STATUS_REQUEST). Esse canal é documentado como "público,
// sem auth, mas não expor além de localhost/LAN confiável" — por isso este bridge (que já está
// na mesma VPS que o WorldServer) fala TCP direto com ele e expõe só o resultado (status/contagem
// de jogadores) via HTTP autenticado, em vez do site tentar falar TCP bruto de fora.
public static class WorldServerStatusClient
{
    private const byte MsgGetServerStatusRequest = 15;
    private const byte MsgGetServerStatusResponse = 16;

    public sealed record ServerStatus(bool Online, int PlayersOnline);

    public static async Task<ServerStatus> GetStatusAsync(string host, int port, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeoutCts = new CancellationTokenSource(timeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var stream = client.GetStream();

            await SendMessageAsync(stream, [MsgGetServerStatusRequest], linked.Token).ConfigureAwait(false);
            var resp = await RecvMessageAsync(stream, linked.Token).ConfigureAwait(false);

            if (resp.Length < 3 || resp[0] != MsgGetServerStatusResponse)
            {
                return new ServerStatus(false, 0);
            }

            int online = resp[1] | (resp[2] << 8);
            return new ServerStatus(true, online);
        }
        catch
        {
            // Servidor offline, host/porta errado, ou side channel inacessível — mostra offline
            // em vez de propagar erro (o site precisa de uma resposta sempre, mesmo que "não sei").
            return new ServerStatus(false, 0);
        }
    }

    private static async Task SendMessageAsync(NetworkStream stream, byte[] payload, CancellationToken ct)
    {
        var len = BitConverter.GetBytes((uint)payload.Length);
        await stream.WriteAsync(len, ct).ConfigureAwait(false);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        }
    }

    private static async Task<byte[]> RecvMessageAsync(NetworkStream stream, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        await ReadExactAsync(stream, lenBuf, ct).ConfigureAwait(false);
        uint len = BitConverter.ToUInt32(lenBuf);
        if (len == 0 || len > (1 << 20))
        {
            return [];
        }
        var buf = new byte[len];
        await ReadExactAsync(stream, buf, ct).ConfigureAwait(false);
        return buf;
    }

    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
            if (read <= 0)
            {
                throw new IOException("Connection closed.");
            }
            total += read;
        }
    }
}
