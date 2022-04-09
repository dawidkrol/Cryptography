//#define calculation_of_hashes
//#define symmetric_encryption
//#define asymmetric_encryption_RSA
#define asymmetric_encryption_RSA_PipeStream


#if calculation_of_hashes
calculation_of_hashes("dawid", "dawid");

#elif symmetric_encryption
using System.IO.Pipes;

symmetric_encryption("symmetric encryption");

#elif asymmetric_encryption_RSA

asymmetric_encryption_RSA("asymmetric encryption");

#elif asymmetric_encryption_RSA_PipeStream

asymmetric_encryption_RSA_PipeStream();

#endif

bool calculation_of_hashes(string first, string sec)
{

    var textinByte = Encoding.UTF8.GetBytes(first);
    var textinByte2 = Encoding.UTF8.GetBytes(sec);

    var a = SHA256.Create().ComputeHash(textinByte);
    var b = SHA256.Create().ComputeHash(textinByte2);

    string s1 = Convert.ToBase64String(a, 0, a.Length);
    string s2 = Convert.ToBase64String(b, 0, b.Length);

    Console.WriteLine("s1 = {0}", s1);
    Console.WriteLine($"s2 = {s2}");

    var output = s1 == s2;

    Console.WriteLine("Equals? : {0}", output);

    return output;
}

void symmetric_encryption(string data)
{
    byte[] key = new byte[16];
    byte[] iv = new byte[16];

    RandomNumberGenerator random = RandomNumberGenerator.Create();
    random.GetBytes(key);
    random.GetBytes(iv);

    using (Aes algoritm = Aes.Create())
    {
        using ICryptoTransform encryptor = algoritm.CreateEncryptor(key,iv);
        using Stream s = new FileStream("CryptoFile.txt", FileMode.OpenOrCreate);
        using Stream c = new CryptoStream(s, encryptor, CryptoStreamMode.Write);
        using Stream d = new DeflateStream(c, CompressionMode.Compress);
        using var e = new StreamWriter(d);
        e.Write(data);
    };

    using (Aes aes = Aes.Create())
    {
        using ICryptoTransform crypto = aes.CreateDecryptor(key, iv);
        using Stream s = new FileStream("CryptoFile.txt", FileMode.Open);
        using Stream k = new CryptoStream(s, crypto, CryptoStreamMode.Read);
        using Stream d = new DeflateStream(k, CompressionMode.Decompress);
        using var stream = new StreamReader(d);
        Console.WriteLine(stream.ReadToEnd());
    }
}

void asymmetric_encryption_RSA(string message)
{
    using(var rsa = new RSACryptoServiceProvider())
    {
        File.WriteAllText("PublickKeyOnly.xml",rsa.ToXmlString(false));
        File.WriteAllText("publicPrivate.xml", rsa.ToXmlString(true));
    }

    byte[] data = Encoding.UTF8.GetBytes(message);

    string publicKeyOnly = File.ReadAllText("PublickKeyOnly.xml");
    string publicPrivate = File.ReadAllText("publicPrivate.xml");

    byte[] encrypted, decrypted;

    using(var rsaPublicOnly = new RSACryptoServiceProvider())
    {
        rsaPublicOnly.FromXmlString(publicKeyOnly);
        encrypted = rsaPublicOnly.Encrypt(data, true);
    }

    using(var rsapublicPrivate = new RSACryptoServiceProvider())
    {
        rsapublicPrivate.FromXmlString(publicPrivate);
        decrypted = rsapublicPrivate.Decrypt(encrypted, true);
    }

    Console.WriteLine(Encoding.UTF8.GetString(decrypted));
}

void asymmetric_encryption_RSA_PipeStream()
{
    byte[] publicKeyOnly;
    byte[] publicPrivate;

    using (var rsa = new RSACryptoServiceProvider())
    {
        publicKeyOnly = rsa.ExportCspBlob(false);
        publicPrivate = rsa.ExportCspBlob(true);
    }
    using var s = new NamedPipeServerStream("Cryptography");
    s.WaitForConnection();
    s.Write(publicKeyOnly, 0, publicKeyOnly.Length);

    byte[] lenInBytes = new byte[4];
    s.Read(lenInBytes, 0, lenInBytes.Length);

    int len = BitConverter.ToInt32(lenInBytes, 0);
    byte[] buffer = new byte[len];

    s.Read(buffer, 0, buffer.Length);

    using (var rsa = new RSACryptoServiceProvider())
    {
        rsa.ImportCspBlob(publicPrivate);
        buffer = rsa.Decrypt(buffer, true);
    }

    Console.WriteLine(Encoding.UTF8.GetString(buffer));
}