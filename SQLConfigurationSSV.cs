using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using static SafeSecretsVaultOnHostDirectory.OpenSSL;
using static SafeSecretsVaultOnHostDirectory.Stremer;

namespace SafeSecretsVaultOnHostDirectory
{
    public class SQLConfigurationSSV : IConfigurationSSV
    {
        private static readonly string? path = Directory.GetCurrentDirectory();
        private static readonly string? pathStringAppsettings = System.IO.Path.Combine(path, "appsettings.json");
        private static readonly string? pathBin = Path.Combine(path, "secrets.bin");
        private static string? dicrSec = null;
        private static Stream? stremer = null;
        private IConfiguration? config { get; set; }
        private IConfiguration Configuration { get; }

        public SQLConfigurationSSV(IConfiguration configuration)
        {
            Configuration = configuration;
            Configuration = ISafeSecrets(Configuration["UserSecretsApiKey"]);

        }
        public IConfiguration ISafeSecrets(string UserSecretsApiKey)
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

     
    }
}
