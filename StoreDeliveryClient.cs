using System.Net.Sockets;
using System.Text;

namespace AccountBridge;

// Fala com o canal novo do WorldServer (CStoreDeliveryChannel, porta 27602
// por padrão) — diferente do WorldServerStatusClient (porta 27601, sem
// auth, só leitura): esse canal CONCEDE ITEM, então carrega um segredo
// compartilhado (WORLDSERVER_DELIVERY_SECRET) dentro de cada pedido, mesmo
// rodando na mesma VPS/LAN confiável. Mesmo formato de fio (prefixo de 4
// bytes little-endian + payload) que o canal de status, pra consistência.
public static class StoreDeliveryClient
{
    private const byte MsgDeliverItemRequest = 1;
    private const byte MsgDeliverItemResponse = 2;
    private const int ItemCodeFieldLength = 16;

    public enum DeliveryStatus : byte
    {
        Bag = 0,
        Mail = 1,
        NotFound = 2,
        Error = 3,
    }

    public sealed record DeliveryResult(bool Ok, DeliveryStatus Status);

    public static async Task<DeliveryResult> DeliverAsync(
        string host,
        int port,
        string secret,
        uint characterSerial,
        string itemCode,
        uint amount,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeoutCts = new CancellationTokenSource(timeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            using var stream = client.GetStream();

            var payload = BuildRequest(secret, characterSerial, itemCode, amount);
            await SendMessageAsync(stream, payload, linked.Token).ConfigureAwait(false);
            var resp = await RecvMessageAsync(stream, linked.Token).ConfigureAwait(false);

            if (resp.Length < 2 || resp[0] != MsgDeliverItemResponse)
            {
                return new DeliveryResult(false, DeliveryStatus.Error);
            }

            var status = (DeliveryStatus)resp[1];
            return new DeliveryResult(status is DeliveryStatus.Bag or DeliveryStatus.Mail, status);
        }
        catch
        {
            // WorldServer fora do ar, host/porta errado, timeout — quem chama decide se tenta de novo
            // (ver deliveries.status='queued' no site, retry via cron).
            return new DeliveryResult(false, DeliveryStatus.Error);
        }
    }

    private static byte[] BuildRequest(string secret, uint characterSerial, string itemCode, uint amount)
    {
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        if (secretBytes.Length > 255)
        {
            throw new InvalidOperationException("WORLDSERVER_DELIVERY_SECRET grande demais (máx 255 bytes).");
        }

        var itemCodeBytes = new byte[ItemCodeFieldLength];
        var itemCodeSrc = Encoding.ASCII.GetBytes(itemCode);
        Array.Copy(itemCodeSrc, itemCodeBytes, Math.Min(itemCodeSrc.Length, ItemCodeFieldLength));

        using var ms = new MemoryStream();
        ms.WriteByte(MsgDeliverItemRequest);
        ms.WriteByte((byte)secretBytes.Length);
        ms.Write(secretBytes);
        ms.Write(BitConverter.GetBytes(characterSerial));
        ms.Write(itemCodeBytes);
        ms.Write(BitConverter.GetBytes(amount));
        return ms.ToArray();
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
