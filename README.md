# Safe Secrets Vault on Host Directory

[![Version](https://img.shields.io/badge/Version-7.0.5-blue)](https://github.com/sultanaalyami/Safe-Secrets-Vault-on-Host/releases/tag/v7.0.5)
[![License](https://img.shields.io/badge/License-CC0%201.0%20Universal-lightgrey)](https://creativecommons.org/publicdomain/zero/1.0/)

The Safe Secrets Vault on Host Directory is a secure solution for storing secrets in an encrypted file using OpenSSL and RijndaelManaged techniques. It provides a reliable and convenient way to store and retrieve secrets from anywhere within your application.

## Key Features

- Strong encryption algorithms to ensure the security of secrets.
- Easy integration with OpenSSL and RijndaelManaged techniques for file encryption.
- Secrets are stored in an encrypted database for added protection.
- Simple and efficient retrieval of secrets from any part of the application.
- Comprehensive error handling and logging for easier troubleshooting.
- Backward compatibility with previous versions for smooth upgrades.

## Installation

You can install the Safe Secrets Vault on Host Directory package via [NuGet](https://www.nuget.org/packages/Safe.Secrets.Vault.On.Host.Directory/) by running the following command:

```shell
dotnet add package Safe.Secrets.Vault.On.Host.Directory --version 7.0.5
```

## Usage

1. Install the package using NuGet by following the installation instructions above.

2. In your `Program.cs` file, add the following using statement at the top:

   ```csharp
   using SafeSecretsVaultOnHostDirectory;
   ```

3. Inside the `Main` method of your application, add the following lines at the beginning:

   ```csharp
   string key = builder.Configuration["UserSecretsApiKey"];
   var config = Stremer.SafeSecrets(Assembly.GetExecutingAssembly(), builder.Configuration["UserSecretsApiKey"]);
   // Add an example code snippet here for illustration
   ```

4. After that, you can retrieve secrets by using the following code:

   ```csharp
   var _GetConnectionString = config["DefaultConnection"];
   ```

   This will retrieve the value of the `DefaultConnection` key from the secrets file in JSON format.

5. Alternatively, you can inject the secrets into your application by adding the following code in your controller or class:

   ```csharp
   public class Controller : Controller
   {
       private IConfiguration Configuration { get; }

       public Controller(IConfiguration configuration)
       {
           Configuration = configuration;
           Configuration = Stremer.DecryptSecrets(Configuration["SecretsApiKey"]);
           // other constructor logic...
       }

       public async Task<IActionResult> Index()
       {
           var UserAuthNSection = Configuration.GetSection("Authentication:User");
           // more code...
       }
   }
   ```

   This way, you can securely access the secrets within your controller or class.

For more details on how to use the Safe Secrets Vault on Host Directory, please refer to the [Documentation](https://github.com/sultanaalyami/Safe-Secrets-Vault-on-Host/wiki).

## Contributing

Contributions are welcome! Please see the [Contributing Guide](CONTRIBUTING.md) for more details.

## License

This project is licensed under the [Creative Commons Zero v1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/) License. You are free
