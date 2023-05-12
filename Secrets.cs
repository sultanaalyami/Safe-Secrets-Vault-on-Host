using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Text;

namespace SafeSecretsVaultOnHostDirectory
{
    public static class Secrets
    {



        public static string EncodeBase64(this string value)
        {

            return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(value));
        }

        public static string DecodeBase64(this string value)
        {
            byte[] valueBytes = WebEncoders.Base64UrlDecode(value);
            return Encoding.UTF8.GetString(valueBytes);
        }
        public static string HashSha256(this string directory)
        {

            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(directory);
            byte[] hashValue;

            using (SHA256 mySHA256 = SHA256.Create())
            {
                hashValue = mySHA256.ComputeHash(keyByte);
                // Compute and print the hash values for each file in directory.
            }
            return ByteToString(hashValue);
        }
        private static string ByteToString(byte[] buff)
        {
            string sbinary = "";

            for (int i = 0; i <= buff.Length - 1; i++)
                // hex format
                sbinary += buff[i].ToString("X2");
            return (sbinary);
        }
    }
}
