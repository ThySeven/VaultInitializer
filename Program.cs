using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using VaultSharp.Core;
using NLog.Web;
using NLog;
using VaultInitializer;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings()
.GetCurrentClassLogger();


logger.Debug("init main");
AuctionCoreLogger.Logger.Info("Initializing vault secrets");
var EndPoint = Environment.GetEnvironmentVariable("VAULT_IP");
var httpClientHandler = new HttpClientHandler();
httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => { return true; };
IVaultClient vaultClient = null;

// Initialize the Vault client
while (vaultClient == null)
{
    try
    {
        IAuthMethodInfo authMethod = new TokenAuthMethodInfo(Environment.GetEnvironmentVariable("VAULT_SECRET"));
        // Initialize settings. You can also set proxies, custom delegates etc. here.
        var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
        {
            Namespace = "",
            MyHttpClientProviderFunc = handler
                => new HttpClient(httpClientHandler)
                {
                    BaseAddress = new Uri(EndPoint)
                }
        };
        vaultClient = new VaultClient(vaultClientSettings);
        AuctionCoreLogger.Logger.Info("Initializing Vault Setup");
    }
    catch (Exception ex)
    {
        Console.WriteLine("Vault is not available yet. Retrying in 5 seconds...");
        Console.WriteLine(ex.Message);
        AuctionCoreLogger.Logger.Warn("Vault is not available yet. Retrying in 5 seconds...");
        AuctionCoreLogger.Logger.Warn(ex.Message);
        Thread.Sleep(5000);
    }
}

bool secretsWritten = false;
while (!secretsWritten)
{
    Secret<SecretData> kv2Secret = null;
    try
    {
        kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "jwt", mountPoint: "secret");

        if (kv2Secret.Data.Data.ContainsKey("secret") && kv2Secret.Data.Data.ContainsKey("issuer") && kv2Secret.Data.Data.ContainsKey("internalApiKey"))
        {
            // Secret is already written, exit the loop.
            Console.WriteLine("Secrets already present.");
            AuctionCoreLogger.Logger.Info("Secrets already present");
            secretsWritten = true;
        }
    }
    catch (VaultApiException e)
    {
        // Handle the case where the secret does not exist.
        if (e.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            var dataToCreate = new Dictionary<string, object>
            {
                { "secret", Environment.GetEnvironmentVariable("JWTSecret") },
                { "issuer", Environment.GetEnvironmentVariable("JWTIssuer") },
                { "internalApiKey", "ThySevenSecretInternalApiKey" }
            };
            // Create the secret since it wasn't found
            await vaultClient.V1.Secrets.KeyValue.V2.WriteSecretAsync(path: "jwt", dataToCreate, mountPoint: "secret");

            // Optionally, you might want to read it back or just proceed with the data you have.
            kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "jwt", mountPoint: "secret");

            if (kv2Secret.Data.Data["secret"] != null && kv2Secret.Data.Data["issuer"] != null && kv2Secret.Data.Data["internalApiKey"] != null)
            {
                Console.WriteLine("Secrets written successfully.");
                AuctionCoreLogger.Logger.Info("Secrets written successfully.");
                secretsWritten = true;
            }
        }
        else
        {
            Console.WriteLine(Environment.GetEnvironmentVariable("JWTSecret"));
            Console.WriteLine(Environment.GetEnvironmentVariable("JWTIssuer"));
            Console.WriteLine(e.Message);
            AuctionCoreLogger.Logger.Warn(e.Message);
        }
    }
    catch (Exception e)
    {
        Console.WriteLine(Environment.GetEnvironmentVariable("JWTSecret"));
        Console.WriteLine(Environment.GetEnvironmentVariable("JWTIssuer"));
        // Handle unexpected exceptions.
        Console.WriteLine(e.Message);
        AuctionCoreLogger.Logger.Warn(e.Message);
    }

    if (!secretsWritten)
    {
        Console.WriteLine("Retrying in 5 seconds...");
        AuctionCoreLogger.Logger.Info("Retrying in 5 seconds...");
        Thread.Sleep(5000);
    }
}
