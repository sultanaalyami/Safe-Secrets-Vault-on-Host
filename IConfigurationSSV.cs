using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SafeSecretsVaultOnHostDirectory
{



    public interface IConfigurationSSV
    {


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
        IConfiguration ISafeSecrets(string UserSecretsApiKey);

    
    }
}
