using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using VaultSharp.Core;

var EndPoint = Environment.GetEnvironmentVariable("VAULT_IP");
var httpClientHandler = new HttpClientHandler();
httpClientHandler.ServerCertificateCustomValidationCallback =
(message, cert, chain, sslPolicyErrors) => { return true; };
IVaultClient vaultClient = null;
try
{
    IAuthMethodInfo authMethod =
    new TokenAuthMethodInfo(Environment.GetEnvironmentVariable("VAULT_SECRET"));
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
}
catch(Exception ex)
{
    Console.WriteLine(ex);
}

Secret<SecretData> kv2Secret = null;
try
{
    kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "jwt", mountPoint: "secret");
}
catch (VaultApiException e)
{
    // Handle the case where the secret does not exist. 
    // For example, you may choose to create it here.
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
    if (kv2Secret.Data.Data["secret"] != null & kv2Secret.Data.Data["issuer"] != null & kv2Secret.Data.Data["internalApiKey"] != null)
        Console.WriteLine("Secrets written");
}
catch (Exception e)
{
    // Handle unexpected exceptions.
    Console.WriteLine(e);
}

