using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace AccountBridge;

// Copia exata de AccountServer/Security/CryptoHelper.cs — mesmos parametros
// Argon2id, mesma derivacao de chave HMAC/AES, pra ficar byte-a-byte
// compativel com o hash ja gravado em tbl_rfaccount pelo AccountServer.
// Se um dia isso mudar la, muda aqui tambem (ou promove pra um pacote
// compartilhado entre os dois projetos).
public static class CryptoHelper
{
    public const int AesGcmNonceSize = 12;
    public const int AesGcmTagSize = 16;

    public static byte[] ComputeHmacSha256(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        using var hmac = new HMACSHA256(key.ToArray());
        return hmac.ComputeHash(data.ToArray());
    }

    public static byte[] EncryptAesGcm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        var nonce = RandomNumberGenerator.GetBytes(AesGcmNonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesGcmTagSize];

        using var aes = new AesGcm(key, AesGcmTagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var payload = new byte[AesGcmNonceSize + AesGcmTagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, payload, nonce.Length, tag.Length);
        Buffer.BlockCopy(ciphertext, 0, payload, nonce.Length + tag.Length, ciphertext.Length);
        return payload;
    }

    public static byte[] DecryptAesGcm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> associatedData = default)
    {
        if (payload.Length < AesGcmNonceSize + AesGcmTagSize)
        {
            throw new ArgumentException("Payload too small.", nameof(payload));
        }

        var nonce = payload.Slice(0, AesGcmNonceSize);
        var tag = payload.Slice(AesGcmNonceSize, AesGcmTagSize);
        var ciphertext = payload.Slice(AesGcmNonceSize + AesGcmTagSize);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, AesGcmTagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    public static byte[] HashArgon2id(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        using var argon2 = new Argon2id(password.ToArray())
        {
            Salt = salt.ToArray(),
            DegreeOfParallelism = 1,
            MemorySize = 65536,
            Iterations = 3
        };
        return argon2.GetBytes(32);
    }

    public static bool VerifyArgon2id(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> expected)
    {
        var hash = HashArgon2id(password, salt);
        return CryptographicOperations.FixedTimeEquals(hash, expected);
    }
}
