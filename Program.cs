using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using VaultSharp.Core;

public static class VaultInitializerFunction
{
    private static readonly HttpClientHandler HttpClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
    };

    [FunctionName("VaultInitializerFunction")]
    public static async Task Run(
        [TimerTrigger("0 */5 * * * *")] TimerInfo myTimer, ILogger log)
    {
        log.LogInformation("C# Timer trigger function executed at: {time}", DateTime.Now);
        await InitializeVaultSecrets(log);
    }

    [FunctionName("VaultInitializerHttpFunction")]
    public static async Task<IActionResult> RunHttp(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req, ILogger log)
    {
        log.LogInformation("C# HTTP trigger function executed at: {time}", DateTime.Now);
        await InitializeVaultSecrets(log);
        return new OkObjectResult("Vault secrets initialization triggered via HTTP.");
    }

    private static async Task InitializeVaultSecrets(ILogger log)
    {
        string vaultIp = Environment.GetEnvironmentVariable("VAULT_IP");
        string vaultSecret = Environment.GetEnvironmentVariable("VAULT_SECRET");
        string jwtSecret = Environment.GetEnvironmentVariable("JWTSecret");
        string jwtIssuer = Environment.GetEnvironmentVariable("JWTIssuer");

        IVaultClient vaultClient = null;

        while (vaultClient == null)
        {
            try
            {
                IAuthMethodInfo authMethod = new TokenAuthMethodInfo(vaultSecret);
                var vaultClientSettings = new VaultClientSettings(vaultIp, authMethod)
                {
                    Namespace = "",
                    MyHttpClientProviderFunc = handler => new HttpClient(HttpClientHandler)
                    {
                        BaseAddress = new Uri(vaultIp)
                    }
                };
                vaultClient = new VaultClient(vaultClientSettings);
                log.LogInformation("Vault client initialized successfully.");
                break;
            }
            catch (Exception ex)
            {
                log.LogWarning("Vault is not available yet. Retrying in 5 seconds... {message}", ex.Message);
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
                    log.LogInformation("Secrets already present.");
                    secretsWritten = true;
                }
            }
            catch (VaultApiException e)
            {
                if (e.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    var dataToCreate = new Dictionary<string, object>
                    {
                        { "secret", jwtSecret },
                        { "issuer", jwtIssuer },
                        { "internalApiKey", "ThySevenSecretInternalApiKey" }
                    };
                    await vaultClient.V1.Secrets.KeyValue.V2.WriteSecretAsync(path: "jwt", dataToCreate, mountPoint: "secret");

                    kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "jwt", mountPoint: "secret");

                    if (kv2Secret.Data.Data["secret"] != null && kv2Secret.Data.Data["issuer"] != null && kv2Secret.Data.Data["internalApiKey"] != null)
                    {
                        log.LogInformation("Secrets written successfully.");
                        secretsWritten = true;
                    }
                }
                else
                {
                    log.LogWarning("Error reading secrets: {message}", e.Message);
                }
            }
            catch (Exception e)
            {
                log.LogError("Unexpected error: {message}", e.Message);
            }

            if (!secretsWritten)
            {
                log.LogInformation("Retrying in 5 seconds...");
                Thread.Sleep(5000);
            }
        }
    }
}
