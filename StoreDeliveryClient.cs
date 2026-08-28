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
    private const byte MsgDeliverPackageRequest = 3;
    private const byte MsgDeliverPackageResponse = 4;
    private const int ItemCodeFieldLength = 16;
    private const int AccountUsernameFieldLength = 16;

    public enum DeliveryStatus : byte
    {
        Bag = 0,
        Mail = 1,
        NotFound = 2,
        Error = 3,
    }

    public enum CashCreditStatus : byte
    {
        Credited = 0,
        Skipped = 1,
        Error = 2,
    }

    public sealed record DeliveryResult(bool Ok, DeliveryStatus Status);

    public sealed record PackageItem(string ItemCode, uint Amount);

    public sealed record PackageDeliveryResult(bool Ok, CashCreditStatus CashStatus, IReadOnlyList<DeliveryStatus> ItemStatuses);

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

    // Entrega o pacote inteiro (Cash + N itens) numa call so' - mesmo canal, opcode novo (3/4).
    // accountUsername vem do site (que ja sabe a conta logada) - o WorldServer nao precisa
    // descobrir dono do personagem, so' credita Cash nessa conta e itens nesse personagem.
    public static async Task<PackageDeliveryResult> DeliverPackageAsync(
        string host,
        int port,
        string secret,
        uint characterSerial,
        string accountUsername,
        int cashAmount,
        IReadOnlyList<PackageItem> items,
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

            var payload = BuildPackageRequest(secret, characterSerial, accountUsername, cashAmount, items);
            await SendMessageAsync(stream, payload, linked.Token).ConfigureAwait(false);
            var resp = await RecvMessageAsync(stream, linked.Token).ConfigureAwait(false);

            if (resp.Length < 3 || resp[0] != MsgDeliverPackageResponse)
            {
                return new PackageDeliveryResult(false, CashCreditStatus.Error, []);
            }

            var cashStatus = (CashCreditStatus)resp[1];
            int itemCount = resp[2];
            if (resp.Length < 3 + itemCount)
            {
                return new PackageDeliveryResult(false, CashCreditStatus.Error, []);
            }

            var itemStatuses = new DeliveryStatus[itemCount];
            for (int i = 0; i < itemCount; i++)
            {
                itemStatuses[i] = (DeliveryStatus)resp[3 + i];
            }

            bool cashOk = cashStatus is CashCreditStatus.Credited or CashCreditStatus.Skipped;
            bool itemsOk = itemStatuses.All(st => st is DeliveryStatus.Bag or DeliveryStatus.Mail);
            return new PackageDeliveryResult(cashOk && itemsOk, cashStatus, itemStatuses);
        }
        catch
        {
            // WorldServer fora do ar, host/porta errado, timeout — quem chama decide se tenta de novo.
            return new PackageDeliveryResult(false, CashCreditStatus.Error, []);
        }
    }

    private static byte[] BuildPackageRequest(string secret, uint characterSerial, string accountUsername, int cashAmount, IReadOnlyList<PackageItem> items)
    {
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        if (secretBytes.Length > 255)
        {
            throw new InvalidOperationException("WORLDSERVER_DELIVERY_SECRET grande demais (máx 255 bytes).");
        }
        if (items.Count > 255)
        {
            throw new InvalidOperationException("Pacote com itens demais (máx 255).");
        }

        var accountBytes = new byte[AccountUsernameFieldLength];
        var accountSrc = Encoding.ASCII.GetBytes(accountUsername);
        Array.Copy(accountSrc, accountBytes, Math.Min(accountSrc.Length, AccountUsernameFieldLength));

        using var ms = new MemoryStream();
        ms.WriteByte(MsgDeliverPackageRequest);
        ms.WriteByte((byte)secretBytes.Length);
        ms.Write(secretBytes);
        ms.Write(BitConverter.GetBytes(characterSerial));
        ms.Write(accountBytes);
        ms.Write(BitConverter.GetBytes(cashAmount));
        ms.WriteByte((byte)items.Count);
        foreach (var item in items)
        {
            var itemCodeBytes = new byte[ItemCodeFieldLength];
            var itemCodeSrc = Encoding.ASCII.GetBytes(item.ItemCode);
            Array.Copy(itemCodeSrc, itemCodeBytes, Math.Min(itemCodeSrc.Length, ItemCodeFieldLength));
            ms.Write(itemCodeBytes);
            ms.Write(BitConverter.GetBytes(item.Amount));
        }
        return ms.ToArray();
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
