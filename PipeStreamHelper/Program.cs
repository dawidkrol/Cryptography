using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;

string dataToSend = "Important message";

using var s = new NamedPipeClientStream("Cryptography");
s.Connect();
byte[] key = new byte[16];

s.Read(key, 0, key.Length);

byte[] encryptedMessage;

using (var RSAprovider = new RSACryptoServiceProvider())
{
    RSAprovider.ImportCspBlob(key);
    encryptedMessage = RSAprovider.Encrypt(Encoding.UTF8.GetBytes(dataToSend), true);
}
var len = BitConverter.GetBytes(encryptedMessage.Length);

s.Write(len, 0, len.Length);

s.Write(encryptedMessage, 0, encryptedMessage.Length);