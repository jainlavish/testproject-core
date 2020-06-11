using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Security
{
    /// <summary>
    /// Provides the functionality to encrypt and decrypt the text based on Rijndael algorithm
    /// It used the secrete key from the azure vault 
    /// </summary>
    public class CryptoService : ICryptoService
    {
        //This constant Keysize is used to determine the encryption key in bytes
        private const int Keysize = 256;

        #region ICryptoService implementation

        /// <summary>
        /// Encrypts requested plain text to encoded bytes based on Rijndael algorithm
        /// <see cref="ICryptoService.Encrypt(string)"/>
        /// </summary>
        public byte[] Encrypt(string plainText, string secretKey, string iv, string salt)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(secretKey))
                throw new ArgumentNullException("secretKey");

            byte[] encrypted = null;
            using var aesAlgCipher = CreateCipher(secretKey, iv, salt);

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlgCipher.CreateEncryptor(aesAlgCipher.Key, aesAlgCipher.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        /// <summary>
        /// Decrypts requested encoded byte array to plain text based on Rijndael algorithm
        /// <see cref="ICryptoService.Decrypt(byte[])"/>
        /// </summary>    
        public string Decrypt(byte[] encodedBytes, string secretKey, string iv, string salt)
        {
            // Check arguments.
            if (encodedBytes == null || encodedBytes.Length <= 0)
                throw new ArgumentNullException("encodedBytes");
            if (string.IsNullOrEmpty(secretKey))
                throw new ArgumentNullException("secretKey");        

            // Declare the string used to hold the decrypted text.
            string plaintext = null;

            using var aesAlgCipher = CreateCipher(secretKey, iv, salt);

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlgCipher.CreateDecryptor(aesAlgCipher.Key, aesAlgCipher.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(encodedBytes))
            {
                CryptoStream csDecrypt = null;
                try
                {
                    csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Read the decrypted bytes from the decrypting stream and place them in a string.
                        csDecrypt = null;
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
                finally
                {
                    csDecrypt?.Dispose();
                }
            }

            return plaintext;
        }

        #endregion

        #region Private Methods

        private Aes CreateCipher(string secretKey, string iv, string salt)
        {
            byte[] key = Encoding.UTF8.GetBytes(secretKey);
            byte[] ivByte = new UTF8Encoding().GetBytes(iv);
            byte[] saltByte = new UTF8Encoding().GetBytes(salt);

            key = new Rfc2898DeriveBytes(key, saltByte, 1000).GetBytes(Keysize / 8);

            var myAes = Aes.Create();
            myAes.Key = key;
            myAes.IV = ivByte;
            myAes.Padding = PaddingMode.PKCS7;
            myAes.Mode = CipherMode.CBC;

            return myAes;
        }

        #endregion

    }
}
