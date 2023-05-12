using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Dynamic;
using System.Reflection;
using System.Text;
using static SafeSecretsVaultOnHostDirectory.OpenSSL;

namespace SafeSecretsVaultOnHostDirectory
{
    public static class Stremer
    {
       private static readonly string? path = Directory.GetCurrentDirectory();
       private static readonly string? pathStringAppsettings = System.IO.Path.Combine(path, "appsettings.json");
       private static readonly string? pathBin = Path.Combine(path, "secrets.bin");
       private static string? dicrSec = null;
       private static Stream? stremer = null;
       private static IConfiguration? config = null;

        //
        // Summary:
        //    generation a custom key and also salt By calculating the byte of the Secrets.json.
        //
        // Parameters:
        //   secretsId:
        //    It can be obtained by adding the following code in place.
        //     Assembly.GetExecutingAssembly().GetCustomAttribute<UserSecretsIdAttribute>().UserSecretsId.
        //
        //     
        //     
        //
        // Returns:
        //     A secret key for data recovery will be generated in the form of a stream and will be automatically
        //     saved in the appsettings.json file and will be named by default UserSecretsApiKey

        //
        // Exceptions:
        //   The input must not contain any whitespace or padding characters. Throws System.FormatException
        //     if the input is malformed.
        public static IConfiguration SafeSecrets(this Assembly assembly , string UserSecretsApiKey)
        {

     
            if (!File.Exists(pathBin) || string.IsNullOrEmpty(UserSecretsApiKey))
            {
            var secretsId = assembly.GetCustomAttribute<UserSecretsIdAttribute>().UserSecretsId;
            var secretsPath = PathHelper.GetSecretsPathFromSecretsId(secretsId);
            var fileStream = File.ReadAllBytes(secretsPath);
            string secrets = Encoding.UTF8.GetString(fileStream);
            var secretscount = fileStream.Count().ToString();
            var encr = OpenSSLEncrypt(secrets, secretscount, (secretscount.Length * int.Parse(secretscount)).ToString());
 
            stremer = SecretsStream(encr, secrets);
            config = new ConfigurationBuilder()
                   .AddJsonStream(stremer)
                   .Build();
            
            }
            else
            {
                dicrSec = DecryptSecrets(UserSecretsApiKey , true);
                byte[] byteArray = Encoding.UTF8.GetBytes(dicrSec);
                //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
                stremer = new MemoryStream(byteArray);
                config = new ConfigurationBuilder()
                   .AddJsonStream(stremer)
                   .Build();
            }
            return config;
        }
        //
        // Summary:
        //    generation a custom key and also salt By calculating the byte of the Secrets.json.
        //
        // Parameters:
        //   secretsId:
        //    It can be obtained by adding the following code in place.
        //     Assembly.GetExecutingAssembly().GetCustomAttribute<UserSecretsIdAttribute>().UserSecretsId.
        //
        //     
        //     
        //
        // Returns:
        //     A secret key for data recovery will be generated in the form of a stream and will be automatically
        //     saved in the appsettings.json file and will be named by default UserSecretsApiKey

        //
        // Exceptions:
        //   The input must not contain any whitespace or padding characters. Throws System.FormatException
        //     if the input is malformed.
        public static Stream? SafeSecrets(this Assembly assembly , string UserSecretsApiKey ,CancellationToken token)
        {

     
            if (!File.Exists(pathBin) || string.IsNullOrEmpty(UserSecretsApiKey))
            {
            var secretsId = assembly.GetCustomAttribute<UserSecretsIdAttribute>().UserSecretsId;
            var secretsPath = PathHelper.GetSecretsPathFromSecretsId(secretsId);
            var fileStream = File.ReadAllBytes(secretsPath);
            string secrets = Encoding.ASCII.GetString(fileStream);
            var secretscount = fileStream.Count().ToString();
            var encr = OpenSSLEncrypt(secrets, secretscount, (secretscount.Length * int.Parse(secretscount)).ToString());
 
            stremer = SecretsStream(encr, secrets);
            //config = new ConfigurationBuilder()
            //       .AddJsonStream(stremer)
            //       .Build();
            
            }
            else
            {
                dicrSec = DecryptSecrets(UserSecretsApiKey , true);
                byte[] byteArray = Encoding.UTF8.GetBytes(dicrSec);
                //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
                stremer = new MemoryStream(byteArray);
                //config = new ConfigurationBuilder()
                //   .AddJsonStream(stremer)
                //   .Build();
            }
            return stremer;
        }

        //
        // Summary:
        //    generation a custom key and also salt By calculating the byte of the Secrets.json.
        //
        // Parameters:
        //   secretsId:
        //    It can be obtained by adding the following code in place.
        //     Assembly.GetExecutingAssembly().GetCustomAttribute<UserSecretsIdAttribute>().UserSecretsId.
        //
        //     
        //     
        //
        // Returns:
        //     A secret key for data recovery will be generated in the form of a stream and will be automatically
        //     saved in the appsettings.json file and will be named by default UserSecretsApiKey

        //
        // Exceptions:
        //   The input must not contain any whitespace or padding characters. Throws System.FormatException
        //     if the input is malformed.
        public static IConfiguration SafeSecrets(this string secretsId , string UserSecretsApiKey)
        {
         

            if (!File.Exists(pathBin) || string.IsNullOrEmpty(UserSecretsApiKey))
            {
                var secretsPath = PathHelper.GetSecretsPathFromSecretsId(secretsId);
                var fileStream = File.ReadAllBytes(secretsPath);
                string secrets = Encoding.ASCII.GetString(fileStream);
                var secretscount = fileStream.Count().ToString();
                var encr = OpenSSLEncrypt(secrets, secretscount, (secretscount.Length * int.Parse(secretscount)).ToString());

                 stremer = SecretsStream(encr, secrets);
                 config = new ConfigurationBuilder()
                       .AddJsonStream(stremer)
                       .Build();
               

            }
            else
            {
                dicrSec = DecryptSecrets(UserSecretsApiKey , true);
                byte[] byteArray = Encoding.UTF8.GetBytes(dicrSec);
                //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
                stremer = new MemoryStream(byteArray);
                config = new ConfigurationBuilder()
                   .AddJsonStream(stremer)
                   .Build();
            }
            return config;
        }

        //
        // Summary:
        //    Create a custom key and also salt
        //
        // Parameters:
        //   secretsId:
        //     It can be obtained by adding the following code in place.
        //     Assembly.GetExecutingAssembly().GetCustomAttribute<UserSecretsIdAttribute>().UserSecretsId.
        //
        //     
        //     
        //   passphrase:
        //     A passphrase is a sequence of words or other text used to control access to a computer system,
        //     program or data. It is similar to a password in usage,
        //     but a passphrase is generally longer for added security.
        //     Passphrases are often used to control both access to, and the operation of,
        //     cryptographic programs and systems.
        //
        //   Salt:
        //     In cryptography, a salt is random data that is used as an additional input to a one-way function that hashes data, a password or passphrase.
        //     [1][full citation needed] Salts are used to safeguard passwords in storage. Historically, only a cryptographic hash function of the password was stored on a system, but over time, additional safeguards were developed to protect against duplicate or common passwords being identifiable (as their hashes are identical).
        //     [2] Salting is one such protection.
        //
        // Returns:
        //     A secret key for data recovery will be generated in the form of a stream and will be automatically
        //     saved in the appsettings.json file and will be named by default UserSecretsApiKey.

        //
        // Exceptions:
        //   The input must not contain any whitespace or padding characters. Throws System.FormatException
        //   if the input is malformed.
        public static IConfiguration SafeSecrets(this string secretsId, string passphrase, string Salt , string UserSecretsApiKey)
        {

            if (!File.Exists(pathBin) || string.IsNullOrEmpty(UserSecretsApiKey))
            {
                var secretsPath = PathHelper.GetSecretsPathFromSecretsId(secretsId);
                var fileStream = File.ReadAllBytes(secretsPath);
                string secrets = Encoding.ASCII.GetString(fileStream);
                var secretscount = fileStream.Count().ToString();
                var encr = OpenSSLEncrypt(secrets, passphrase, Salt);

                 stremer = SecretsStream(encr, secrets);
                 config = new ConfigurationBuilder()
                       .AddJsonStream(stremer)
                       .Build();

            }
            else
            {
                dicrSec = DecryptSecrets(UserSecretsApiKey,true);
                byte[] byteArray = Encoding.UTF8.GetBytes(dicrSec);
                //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
                stremer = new MemoryStream(byteArray);
                config = new ConfigurationBuilder()
                   .AddJsonStream(stremer)
                   .Build();
            }
            return config;
        }
        //
        // Summary:
        //    Create a custom key and also salt
        //
        // Parameters:
        //   secretsId:
        //     It can be obtained by adding the following code in place.
        //     Assembly.GetExecutingAssembly().GetCustomAttribute<UserSecretsIdAttribute>().UserSecretsId.
        //
        //     
        //     
        //   passphrase:
        //     A passphrase is a sequence of words or other text used to control access to a computer system,
        //     program or data. It is similar to a password in usage,
        //     but a passphrase is generally longer for added security.
        //     Passphrases are often used to control both access to, and the operation of,
        //     cryptographic programs and systems.
        //
        //   Salt:
        //     In cryptography, a salt is random data that is used as an additional input to a one-way function that hashes data, a password or passphrase.
        //     [1][full citation needed] Salts are used to safeguard passwords in storage. Historically, only a cryptographic hash function of the password was stored on a system, but over time, additional safeguards were developed to protect against duplicate or common passwords being identifiable (as their hashes are identical).
        //     [2] Salting is one such protection.
        //
        // Returns:
        //     A secret key for data recovery will be generated in the form of a stream and will be automatically
        //     saved in the appsettings.json file and will be named by default UserSecretsApiKey.

        //
        // Exceptions:
        //   The input must not contain any whitespace or padding characters. Throws System.FormatException
        //   if the input is malformed.
        public static IConfiguration DecryptSecrets(this string UserSecretsApiKey)
        {
            var filebin = File.ReadAllBytes(pathBin);
            string secretsfilebin = Encoding.ASCII.GetString(filebin);
            dicrSec = OpenSSLDecrypt(secretsfilebin, UserSecretsApiKey);


            // convert string to stream
            byte[] byteArray = Encoding.UTF8.GetBytes(dicrSec);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            stremer = new MemoryStream(byteArray);
            config = new ConfigurationBuilder()
               .AddJsonStream(stremer)
               .Build();
            return config;
        }

        public static string DecryptSecrets(this string UserSecretsApiKey ,bool local)
        {
            var filebin = File.ReadAllBytes(pathBin);
            string secretsfilebin = Encoding.ASCII.GetString(filebin);
            dicrSec = OpenSSLDecrypt(secretsfilebin, UserSecretsApiKey);
            return dicrSec;
        }





        public static Stream SecretsStream(encript encr , string secrets)
        {
            
            var stb = Encoding.ASCII.GetBytes(encr.dataEncrypted);
            //2. Load and modify
            var secretsJson = File.ReadAllText(pathStringAppsettings);
            dynamic? dsecrets = JsonConvert.DeserializeObject<ExpandoObject>(secretsJson, new ExpandoObjectConverter());
            dsecrets.UserSecretsApiKey = encr.key;

            //3. Overwrite the file with changes
            var updatedSecretsJson = JsonConvert.SerializeObject(dsecrets, Formatting.Indented);
            File.WriteAllText(pathStringAppsettings, updatedSecretsJson);

            
            if (File.Exists(pathBin))
            {
                var filebin = File.ReadAllBytes(pathBin);
                string secretsfilebin = Encoding.ASCII.GetString(filebin);
                dicrSec = OpenSSLDecrypt(secretsfilebin, encr.key);
                if (secrets != dicrSec)
                {
                    using (FileStream fs = new FileStream(pathBin, FileMode.Create))
                    {
                        using (BinaryWriter bww = new BinaryWriter(fs))
                        {
                            bww.Write(stb);
                        };

                    };
                }
            }
            else
            {
                using (FileStream fs = new FileStream(pathBin, FileMode.Create))
                {
                    using (BinaryWriter bww = new BinaryWriter(fs))
                    {
                        bww.Write(stb);
                    };

                };
            }


            // convert string to stream
            byte[] byteArray = Encoding.UTF8.GetBytes(dicrSec);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            MemoryStream stream = new MemoryStream(byteArray);

            return stream;
        }
    }
      
}