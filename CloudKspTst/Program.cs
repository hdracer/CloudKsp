/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Hyak.Common;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.Common.Internals;

namespace CloudKspTst
{
    enum KeyOperationType
    {
        CREATE_KEY,
        IMPORT_KEY,
        GET_KEY,
        LIST_KEYVERSIONS,
        UPDATE_KEY,
        DELETE_KEY,
        BACKUP_RESTORE,
        SIGN_VERIFY,
        ENCRYPT_DECRYPT,
        WRAP_UNWRAP,
        CREATE_SECRET,
        GET_SECRET,
        LIST_SECRETS,
        DELETE_SECRET,
        ENCRYPT,
        DECRYPT
    }

    class Program
    {
        static KeyVaultClient keyVaultClient;
        static InputValidator inputValidator;
        static ClientCredential clientCredential;

        //
        // https://github.com/Azure/azure-sdk-for-net/blob/master/src/KeyVault/Microsoft.Azure.KeyVault.Samples/samples/HelloKeyVault/Program.cs
        //
        static void Main(string[] args)
        {
            KeyBundle keyBundle = null; // The key specification and attributes
            SecretBundle secret = null;
            string keyName = string.Empty;
            string secretName = string.Empty;

            inputValidator = new InputValidator(args);

            TracingAdapter.AddTracingInterceptor(new ConsoleTracingInterceptor());
            TracingAdapter.IsEnabled = inputValidator.GetTracingEnabled();

            var clientId = ConfigurationManager.AppSettings["AuthClientId"];
            var clientSecret = ConfigurationManager.AppSettings["AuthClientSecret"];
            clientCredential = new ClientCredential(clientId, clientSecret);

            keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetAccessToken), GetHttpClient());

            // SECURITY: DO NOT USE IN PRODUCTION CODE; FOR TEST PURPOSES ONLY
            //ServicePointManager.ServerCertificateValidationCallback += ( sender, cert, chain, sslPolicyErrors ) => true;

            List<KeyOperationType> successfulOperations = new List<KeyOperationType>();
            List<KeyOperationType> failedOperations = new List<KeyOperationType>();

            foreach (var operation in inputValidator.GetKeyOperations())
            {
                try
                {
                    Console.Out.WriteLine(string.Format("\n\n {0} is in process ...", operation.ToString()));
                    switch (operation)
                    {
                        case KeyOperationType.CREATE_KEY:
                            keyBundle = CreateKey(keyBundle, out keyName);
                            break;

                        case KeyOperationType.IMPORT_KEY:
                            keyBundle = ImportKey(out keyName);
                            break;

                        case KeyOperationType.GET_KEY:
                            keyBundle = GetKey(keyBundle);
                            break;

                        case KeyOperationType.LIST_KEYVERSIONS:
                            ListKeyVersions(keyName);
                            break;

                        case KeyOperationType.UPDATE_KEY:
                            keyBundle = UpdateKey(keyName);
                            break;

                        case KeyOperationType.DELETE_KEY:
                            DeleteKey(keyName);
                            break;

                        case KeyOperationType.BACKUP_RESTORE:
                            keyBundle = BackupRestoreKey(keyName);
                            break;

                        case KeyOperationType.SIGN_VERIFY:
                            SignVerify(keyBundle);
                            break;

                        case KeyOperationType.ENCRYPT_DECRYPT:
                            EncryptDecrypt(keyBundle);
                            break;

                        case KeyOperationType.ENCRYPT:
                            Encrypt(keyBundle);
                            break;

                        case KeyOperationType.DECRYPT:
                            Decrypt(keyBundle);
                            break;

                        case KeyOperationType.WRAP_UNWRAP:
                            WrapUnwrap(keyBundle);
                            break;

                        case KeyOperationType.CREATE_SECRET:
                            secret = CreateSecret(out secretName);
                            break;

                        case KeyOperationType.GET_SECRET:
                            secret = GetSecret(secret.Id);
                            break;

                        case KeyOperationType.LIST_SECRETS:
                            ListSecrets();
                            break;

                        case KeyOperationType.DELETE_SECRET:
                            secret = DeleteSecret(secretName);
                            break;
                    }
                    successfulOperations.Add(operation);
                }
                catch (KeyVaultErrorException exception)
                {
                    // The Key Vault exceptions are logged but not thrown to avoid blocking execution for other commands running in batch
                    Console.Out.WriteLine("Operation failed: {0}", exception.Message);
                    failedOperations.Add(operation);
                }

            }

            Console.Out.WriteLine("\n\n---------------Successful Key Vault operations:---------------");
            foreach (KeyOperationType type in successfulOperations)
                Console.Out.WriteLine("\t{0}", type);

            if (failedOperations.Count > 0)
            {
                Console.Out.WriteLine("\n\n---------------Failed Key Vault operations:---------------");
                foreach (KeyOperationType type in failedOperations)
                    Console.Out.WriteLine("\t{0}", type);
            }

            Console.Out.WriteLine();
            Console.Out.Write("Press enter to continue . . .");
            Console.In.Read();
        }
        /// <summary>
        /// Updates key attributes
        /// </summary>
        /// <param name="keyName"> a global key identifier of the key to update </param>
        /// <returns> updated key bundle </returns>
        private static KeyBundle UpdateKey(string keyName)
        {
            var vaultAddress = inputValidator.GetVaultAddress();
            keyName = (keyName == string.Empty) ? inputValidator.GetKeyId() : keyName;

            // Get key attribute to update
            var keyAttributes = inputValidator.GetUpdateKeyAttribute();
            var updatedKey = keyVaultClient.UpdateKeyAsync(vaultAddress, keyName, attributes: keyAttributes).GetAwaiter().GetResult();

            Console.Out.WriteLine("Updated key:---------------");
            PrintoutKey(updatedKey);

            return updatedKey;
        }

        /// <summary>
        /// Import an asymmetric key into the vault
        /// </summary>
        /// <param name="keyName">Key name</param>
        /// <returns> imported key bundle</returns>
        private static KeyBundle ImportKey(out string keyName)
        {
            var vaultAddress = inputValidator.GetVaultAddress();
            keyName = inputValidator.GetKeyName();
            var isHsm = inputValidator.GetKeyType() == JsonWebKeyType.RsaHsm;

            // Get key bundle which is needed for importing a key
            var keyBundle = inputValidator.GetImportKeyBundle();
            var importedKey = keyVaultClient.ImportKeyAsync(vaultAddress, keyName, keyBundle, isHsm).GetAwaiter().GetResult();

            Console.Out.WriteLine("Imported key:---------------");
            PrintoutKey(importedKey);

            return importedKey;
        }

        /// <summary>
        /// Gets the specified key
        /// </summary>
        /// <param name="keyId"> a global key identifier of the key to get </param>
        /// <returns> retrieved key bundle </returns>
        private static KeyBundle GetKey(KeyBundle key)
        {
            KeyBundle retrievedKey;
            string keyVersion = inputValidator.GetKeyVersion();
            string keyName = inputValidator.GetKeyName(allowDefault: false);

            if (keyVersion != string.Empty || keyName != string.Empty)
            {
                var vaultAddress = inputValidator.GetVaultAddress();
                if (keyVersion != string.Empty)
                {
                    keyName = inputValidator.GetKeyName(true);
                    retrievedKey = keyVaultClient.GetKeyAsync(vaultAddress, keyName, keyVersion).GetAwaiter().GetResult();
                }
                else
                {
                    retrievedKey = keyVaultClient.GetKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();
                }
            }
            else
            {
                // If the key is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : inputValidator.GetKeyId();

                // Get the key using its ID
                retrievedKey = keyVaultClient.GetKeyAsync(keyId).GetAwaiter().GetResult();
            }

            Console.Out.WriteLine("Retrived key:---------------");
            PrintoutKey(retrievedKey);

            //store the created key for the next operation if we have a sequence of operations
            return retrievedKey;
        }

        /// <summary>
        /// List the versions of a key
        /// </summary>
        /// <param name="keyName"> key name</param>
        private static void ListKeyVersions(string keyName)
        {
            var vaultAddress = inputValidator.GetVaultAddress();
            keyName = (keyName == string.Empty) ? inputValidator.GetKeyId() : keyName;

            var numKeyVersions = 0;

            Console.Out.WriteLine("List key versions:---------------");

            var results = keyVaultClient.GetKeyVersionsAsync(vaultAddress, keyName, null).GetAwaiter().GetResult();

            if (results != null)
            {
                foreach(var result in results)
                {
                    Console.Out.WriteLine("\t{0}-{1}", result.Identifier.Name, result.Identifier.Version);
                    numKeyVersions++;
                }
            }

            Console.Out.WriteLine("\n\tNumber of versions of key {0} in the vault: {1}", keyName, numKeyVersions);
        }

        /// <summary>
        /// Created the specified key
        /// </summary>
        /// <param name="keyBundle"> key bundle to create </param>
        /// <returns> created key bundle </returns>
        private static KeyBundle CreateKey(KeyBundle keyBundle, out string keyName)
        {
            // Get key bundle which is needed for creating a key
            keyBundle = keyBundle ?? inputValidator.GetKeyBundle();
            var vaultAddress = inputValidator.GetVaultAddress();
            keyName = inputValidator.GetKeyName();

            var tags = inputValidator.GetTags();

            // Create key in the KeyVault key vault
            var createdKey = keyVaultClient.CreateKeyAsync(vaultAddress, keyName, keyBundle.Key.Kty, keyAttributes: keyBundle.Attributes, tags: tags).GetAwaiter().GetResult();

            Console.Out.WriteLine("Created key:---------------");
            PrintoutKey(createdKey);

            // Store the created key for the next operation if we have a sequence of operations
            return createdKey;
        }


        /// <summary>
        /// Creates or updates a secret
        /// </summary>
        /// <returns> The created or the updated secret </returns>
        private static SecretBundle CreateSecret(out string secretName)
        {
            secretName = inputValidator.GetSecretName();
            string secretValue = inputValidator.GetSecretValue();

            var tags = inputValidator.GetTags();

            var contentType = inputValidator.GetSecretContentType();

            var secret = keyVaultClient.SetSecretAsync(inputValidator.GetVaultAddress(), secretName, secretValue, tags, contentType, inputValidator.GetSecretAttributes()).GetAwaiter().GetResult();

            Console.Out.WriteLine("Created/Updated secret:---------------");
            PrintoutSecret(secret);

            return secret;
        }

        /// <summary>
        /// Gets a secret
        /// </summary>
        /// <param name="secretId"> The secret ID </param>
        /// <returns> The created or the updated secret </returns>
        private static SecretBundle GetSecret(string secretId)
        {
            SecretBundle secret;
            string secretVersion = inputValidator.GetSecretVersion();

            if (secretVersion != string.Empty)
            {
                var vaultAddress = inputValidator.GetVaultAddress();
                string secretName = inputValidator.GetSecretName(true);
                secret = keyVaultClient.GetSecretAsync(vaultAddress, secretName, secretVersion).GetAwaiter().GetResult();
            }
            else
            {
                secretId = secretId ?? inputValidator.GetSecretId();
                secret = keyVaultClient.GetSecretAsync(secretId).GetAwaiter().GetResult();
            }
            Console.Out.WriteLine("Retrieved secret:---------------");
            PrintoutSecret(secret);

            return secret;
        }

        /// <summary>
        /// Lists secrets in a vault
        /// </summary>
        private static void ListSecrets()
        {
            var vaultAddress = inputValidator.GetVaultAddress();
            var numSecretsInVault = 0;

            Console.Out.WriteLine("List secrets:---------------");
            var results = keyVaultClient.GetSecretsAsync(vaultAddress, null).GetAwaiter().GetResult();

            if (results != null)
            {
                foreach(var result in results)
                {
                    Console.Out.WriteLine("\t{0}", result.Identifier.Name);
                }
            }

            Console.Out.WriteLine("\n\tNumber of secrets in the vault: {0}", numSecretsInVault);
        }

        /// <summary>
        /// Deletes secret
        /// </summary>
        /// <param name="secretId"> The secret ID</param>
        /// <returns> The deleted secret </returns>
        private static SecretBundle DeleteSecret(string secretName)
        {
            // If the secret is not initialized get the secret Id from args
            var vaultAddress = inputValidator.GetVaultAddress();
            secretName = (secretName == string.Empty) ? inputValidator.GetSecretName() : secretName;

            var secret = keyVaultClient.DeleteSecretAsync(vaultAddress, secretName).GetAwaiter().GetResult();

            Console.Out.WriteLine("Deleted secret:---------------");
            PrintoutSecret(secret);

            return secret;
        }

        /// <summary>
        /// backup the specified key and then restores the key into a vault
        /// </summary>
        /// <param name="keyId"> a global key identifier of the key to get </param>
        /// <returns> restored key bundle </returns>
        private static KeyBundle BackupRestoreKey(string keyName)
        {
            var vaultAddress = inputValidator.GetVaultAddress();
            keyName = inputValidator.GetKeyName();

            // Get a backup of the key and cache its backup value
            var backupKeyValue = keyVaultClient.BackupKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();
            Console.Out.WriteLine(string.Format(
                "The backup key value contains {0} bytes.\nTo restore it into a key vault this value should be provided!", backupKeyValue.Value.Length));

            // Get the vault address from args or use the default one
            var newVaultAddress = inputValidator.GetVaultAddress();

            // Delete any existing key in that vault.
            keyVaultClient.DeleteKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();

            // Restore the backed up value into the vault
            var restoredKey = keyVaultClient.RestoreKeyAsync(newVaultAddress, backupKeyValue.Value).GetAwaiter().GetResult();

            Console.Out.WriteLine("Restored key:---------------");
            PrintoutKey(restoredKey);

            // Cache the restored key
            return restoredKey;
        }

        /// <summary>
        /// Deletes the specified key
        /// </summary>
        /// <param name="keyId"> a global key identifier of the key to get </param>
        private static void DeleteKey(string keyName)
        {
            // If the key ID is not initialized get the key id from args
            var vaultAddress = inputValidator.GetVaultAddress();
            keyName = (keyName == string.Empty) ? inputValidator.GetKeyName() : keyName;

            // Delete the key with the specified ID
            var keyBundle = keyVaultClient.DeleteKeyAsync(vaultAddress, keyName).GetAwaiter().GetResult();
            Console.Out.WriteLine(string.Format("Key {0} is deleted successfully!", keyBundle.Key.Kid));
        }

        /// <summary>
        /// Wraps a symmetric key and then unwrapps the wrapped key
        /// </summary>
        /// <param name="keyId"> a global key identifier of the key to get </param>
        private static void WrapUnwrap(KeyBundle key)
        {
            KeyOperationResult wrappedKey;

            var algorithm = inputValidator.GetEncryptionAlgorithm();
            byte[] symmetricKey = inputValidator.GetSymmetricKey();

            string keyVersion = inputValidator.GetKeyVersion();

            if (keyVersion != string.Empty)
            {
                var vaultAddress = inputValidator.GetVaultAddress();
                string keyName = inputValidator.GetKeyName(true);
                wrappedKey = keyVaultClient.WrapKeyAsync(vaultAddress, keyName, keyVersion, algorithm, symmetricKey).GetAwaiter().GetResult();
            }
            else
            {
                // If the key ID is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : inputValidator.GetKeyId();

                // Wrap the symmetric key
                wrappedKey = keyVaultClient.WrapKeyAsync(keyId, algorithm, symmetricKey).GetAwaiter().GetResult();
            }

            Console.Out.WriteLine(string.Format("The symmetric key is wrapped using key id {0} and algorithm {1}", wrappedKey.Kid, algorithm));

            // Unwrap the symmetric key
            var unwrappedKey = keyVaultClient.UnwrapKeyAsync(wrappedKey.Kid, algorithm, wrappedKey.Result).GetAwaiter().GetResult();
            Console.Out.WriteLine(string.Format("The unwrapped key is{0}the same as the original key!",
                symmetricKey.SequenceEqual(unwrappedKey.Result) ? " " : " not "));
        }

        /// <summary>
        /// Encrypts a plain text and then decrypts the encrypted text
        /// </summary>
        /// <param name="key"> key to use for the encryption & decryption operations </param>
        private static void EncryptDecrypt(KeyBundle key)
        {
            KeyOperationResult operationResult;

            var algorithm = inputValidator.GetEncryptionAlgorithm();
            var plainText = inputValidator.GetPlainText();

            string keyVersion = inputValidator.GetKeyVersion();

            operationResult = _encrypt(key, keyVersion, algorithm, plainText);

            Console.Out.WriteLine(string.Format("The text is encrypted using key id {0} and algorithm {1}", operationResult.Kid, algorithm));

            // Decrypt the encrypted data
            var decryptedText = keyVaultClient.DecryptAsync(operationResult.Kid, algorithm, operationResult.Result).GetAwaiter().GetResult();

            Console.Out.WriteLine(string.Format("The decrypted text is{0}the same as the original key!",
                plainText.SequenceEqual(decryptedText.Result) ? " " : " not "));
            Console.Out.WriteLine(string.Format("The decrypted text is: {0}",
                Encoding.UTF8.GetString(decryptedText.Result)));
        }

        private static KeyOperationResult _encrypt(KeyBundle key, string keyVersion, string algorithm, byte[] plainText)
        {
            KeyOperationResult operationResult;

            if (keyVersion != string.Empty)
            {
                var vaultAddress = inputValidator.GetVaultAddress();
                string keyName = inputValidator.GetKeyName(true);

                // Encrypt the input data using the specified algorithm
                operationResult = keyVaultClient.EncryptAsync(vaultAddress, keyName, keyVersion, algorithm, plainText).GetAwaiter().GetResult();
            }
            else
            {
                // If the key is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : inputValidator.GetKeyId();
                // Encrypt the input data using the specified algorithm
                operationResult = keyVaultClient.EncryptAsync(keyId, algorithm, plainText).GetAwaiter().GetResult();
            }

            return operationResult;
        }

        /// <summary>
        /// Encrypts plaintext
        /// </summary>
        /// <param name="key"> key to use for the encryption </param>
        private static void Encrypt(KeyBundle key)
        {
            KeyOperationResult operationResult;

            var algorithm = inputValidator.GetEncryptionAlgorithm();
            var plainText = inputValidator.GetPlainText();

            string keyVersion = inputValidator.GetKeyVersion();

            operationResult = _encrypt(key, keyVersion, algorithm, plainText);

            File.WriteAllText("cipherText.txt", Convert.ToBase64String(operationResult.Result));

            Console.Out.WriteLine(string.Format("The text is encrypted using key id {0} and algorithm {1}", operationResult.Kid, algorithm));
            Console.Out.WriteLine(string.Format("Encrypted text, base-64 encoded: {0}", Convert.ToBase64String(operationResult.Result)));
        }

        /// <summary>
        /// Decrypts cipherText
        /// </summary>
        /// <param name="key"> key to use for the decryption </param>
        private static void Decrypt(KeyBundle key)
        {
            KeyOperationResult operationResult;

            var algorithm = inputValidator.GetEncryptionAlgorithm();
            var cipherText = inputValidator.GetCipherText();

            KeyBundle localKey;

            localKey = (key ?? GetKey(null));

            // Decrypt the encrypted data
            operationResult = keyVaultClient.DecryptAsync(localKey.KeyIdentifier.ToString(), algorithm, cipherText).GetAwaiter().GetResult();

            Console.Out.WriteLine(string.Format("The decrypted text is: {0}", Encoding.UTF8.GetString(operationResult.Result)));
        }

        /// <summary>
        /// Signs a hash and then verifies the signature
        /// </summary>
        /// <param name="keyId"> a global key identifier of the key to get </param>
        private static void SignVerify(KeyBundle key)
        {
            KeyOperationResult signature;
            var algorithm = inputValidator.GetSignAlgorithm();
            var digest = inputValidator.GetDigestHash();

            string keyVersion = inputValidator.GetKeyVersion();
            if (keyVersion != string.Empty)
            {
                var vaultAddress = inputValidator.GetVaultAddress();
                string keyName = inputValidator.GetKeyName(true);
                signature = keyVaultClient.SignAsync(vaultAddress, keyName, keyVersion, algorithm, digest).GetAwaiter().GetResult();
            }
            else
            {
                // If the key is not initialized get the key id from args
                var keyId = (key != null) ? key.Key.Kid : inputValidator.GetKeyId();

                // Create a signature
                signature = keyVaultClient.SignAsync(keyId, algorithm, digest).GetAwaiter().GetResult();
            }
            Console.Out.WriteLine(string.Format("The signature is created using key id {0} and algorithm {1} ", signature.Kid, algorithm));

            // Verify the signature
            bool isVerified = keyVaultClient.VerifyAsync(signature.Kid, algorithm, digest, signature.Result).GetAwaiter().GetResult();
            Console.Out.WriteLine(string.Format("The signature is {0} verified!", isVerified ? "" : "not "));
        }

        /// <summary>
        /// Prints out key bundle values
        /// </summary>
        /// <param name="keyBundle"> key bundle </param>
        private static void PrintoutKey(KeyBundle keyBundle)
        {
            Console.Out.WriteLine("Key: \n\tKey ID: {0}\n\tKey type: {1}",
                keyBundle.Key.Kid, keyBundle.Key.Kty);

            var expiryDateStr = keyBundle.Attributes.Expires.HasValue
                ? keyBundle.Attributes.Expires.ToString()
                : "Never";

            var notBeforeStr = keyBundle.Attributes.NotBefore.HasValue
                ? keyBundle.Attributes.NotBefore.ToString()
                : "";

            Console.Out.WriteLine("Key attributes: \n\tIs the key enabled: {0}\n\tExpiry date: {1}\n\tEnable date: {2}",
                keyBundle.Attributes.Enabled, expiryDateStr, notBeforeStr);
        }

        /// <summary>
        /// Prints out secret values
        /// </summary>
        /// <param name="secret"> secret </param>
        private static void PrintoutSecret(SecretBundle secret)
        {
            Console.Out.WriteLine("\n\tSecret ID: {0}\n\tSecret Value: {1}",
                secret.Id, secret.Value);

            var expiryDateStr = secret.Attributes.Expires.HasValue
                ? secret.Attributes.Expires.ToString()
                : "Never";

            var notBeforeStr = secret.Attributes.NotBefore.HasValue
                ? secret.Attributes.NotBefore.ToString()
                : "";

            Console.Out.WriteLine("Secret attributes: \n\tIs the key enabled: {0}\n\tExpiry date: {1}\n\tEnable date: {2}\n\tContent type: {3}",
                secret.Attributes.Enabled, expiryDateStr, notBeforeStr, secret.ContentType);

            PrintoutTags(secret.Tags);
        }

        /// <summary>
        /// Prints out the tags for a key/secret
        /// </summary>
        /// <param name="tags"></param>
        private static void PrintoutTags(IDictionary<string, string> tags)
        {
            if (tags != null)
            {
                Console.Out.Write("\tTags: ");
                foreach (string key in tags.Keys)
                {
                    Console.Out.Write("\n\t\t{0} : {1}", key, tags[key]);
                }
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Gets the access token
        /// </summary>
        /// <param name="authority"> Authority </param>
        /// <param name="resource"> Resource </param>
        /// <param name="scope"> scope </param>
        /// <returns> token </returns>
        public static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, clientCredential);

            return result.AccessToken;
        }

        /// <summary>
        /// Create an HttpClient object that optionally includes logic to override the HOST header
        /// field for advanced testing purposes.
        /// </summary>
        /// <returns>HttpClient instance to use for Key Vault service communication</returns>
        private static HttpClient GetHttpClient()
        {
            return (HttpClientFactory.Create(new InjectHostHeaderHttpMessageHandler()));
        }
    }

    // Contains the validators and parsers of the input argument
    class InputValidator
    {
        string[] args;

        public InputValidator(string[] args)
        {
            this.args = args;
        }

        /// <summary>
        /// Parse input arguments and get the operations list, if no operation is provided all the operations are being performed
        /// </summary>
        /// <returns> the operation list </returns>
        public List<KeyOperationType> GetKeyOperations()
        {
            List<KeyOperationType> keyOperations = new List<KeyOperationType>();
            foreach (var arg in args)
            {
                var result = new KeyOperationType();
                if (Enum.TryParse<KeyOperationType>(arg, true, out result))
                {
                    keyOperations.Add(result);
                }
            }

            // if no operation found use the default
            if (keyOperations.Count == 0)
            {
                Console.Out.WriteLine("No operation is provided. Executing all the key and secret operations!");
                keyOperations.Add(KeyOperationType.CREATE_KEY);
                keyOperations.Add(KeyOperationType.GET_KEY);
                keyOperations.Add(KeyOperationType.IMPORT_KEY);
                keyOperations.Add(KeyOperationType.BACKUP_RESTORE);
                keyOperations.Add(KeyOperationType.SIGN_VERIFY);
                keyOperations.Add(KeyOperationType.WRAP_UNWRAP);
                keyOperations.Add(KeyOperationType.ENCRYPT);
                keyOperations.Add(KeyOperationType.DECRYPT);
                keyOperations.Add(KeyOperationType.UPDATE_KEY);
                keyOperations.Add(KeyOperationType.LIST_KEYVERSIONS);
                keyOperations.Add(KeyOperationType.DELETE_KEY);
                keyOperations.Add(KeyOperationType.CREATE_SECRET);
                keyOperations.Add(KeyOperationType.GET_SECRET);
                keyOperations.Add(KeyOperationType.LIST_SECRETS);
                keyOperations.Add(KeyOperationType.DELETE_SECRET);
            }
            return keyOperations;
        }

        /// <summary>
        /// Gets plain text to be encrypted, if the argument is not provided returns the default plain text
        /// </summary>
        /// <returns> plain text </returns>
        public byte[] GetPlainText()
        {
            var tag = "-text";
            var text = GetArgumentValue(tag);

            if (text == string.Empty)
            {
                Console.Out.WriteLine(tag + " is not provided. Using default value!");
                text = File.ReadAllText("plainText.txt");
            }

            return System.Text.Encoding.UTF8.GetBytes(text);
        }

        /// <summary>
        /// Gets plain text to be encrypted, if the argument is not provided returns the default plain text
        /// </summary>
        /// <returns> plain text </returns>
        public byte[] GetCipherText()
        {
            var tag = "-text";
            var text = GetArgumentValue(tag);

            if (text == string.Empty)
            {
                Console.Out.WriteLine(tag + " is not provided. Using default value!");
                text = File.ReadAllText("cipherText.txt");
            }

            return Convert.FromBase64String(text);
        }

        /// <summary>
        /// Gets digest hash value, if the argument is not provided returns the default digest value
        /// </summary>
        /// <returns> digest hash </returns>
        public byte[] GetDigestHash()
        {
            var tag = "-digestfile";
            var digestfile = GetArgumentValue(tag);
            var digest = RandomHash<SHA256CryptoServiceProvider>(32);
            if (digestfile != string.Empty)
            {
                digest = File.ReadAllBytes(digestfile);
            }
            else
            {
                Console.Out.WriteLine(tag + " is not provided. Using default value!");
            }
            return digest;
        }

        /// <summary>
        /// Gets sign algorithm, if the argument is not provided returns the default sign algorithm
        /// </summary>
        /// <returns> sign algorithm </returns>
        public string GetSignAlgorithm()
        {
            var tag = "-algo";
            var algorithm = GetArgumentValue(tag);
            if (algorithm == string.Empty)
            {
                algorithm = JsonWebKeySignatureAlgorithm.RS256;
                Console.Out.WriteLine(tag + " is not provided. Using default value!");
            }
            return algorithm;
        }

        /// <summary>
        /// Gets encryption algorithm, if the argument is not provided returns the default encryption algorithm
        /// </summary>
        /// <returns> encryption algorithm </returns>
        public string GetEncryptionAlgorithm()
        {
            var tag = "-algo";
            var algorithm = GetArgumentValue(tag);
            if (algorithm == string.Empty)
            {
                algorithm = JsonWebKeyEncryptionAlgorithm.RSAOAEP;
                Console.Out.WriteLine(tag + " is not provided. Using default value!");
            }
            return algorithm;
        }

        /// <summary>
        /// Gets symmetric key, if the argument is not provided returns the default symmetric key
        /// </summary>
        /// <returns> symmetric key </returns>
        public byte[] GetSymmetricKey()
        {
            var tag = "-symkeyfile";
            var symmetricKeyFile = GetArgumentValue(tag);
            var symmetricKey = SymmetricAlgorithm.Create().Key;
            if (symmetricKeyFile != string.Empty)
            {
                symmetricKey = File.ReadAllBytes(symmetricKeyFile);
            }
            else
            {
                Console.Out.WriteLine(tag + " is not provided. Using default value!");
            }
            return symmetricKey;
        }

        /// <summary>
        /// Gets vault address, if the argument is not provided returns the address of the default vault
        /// </summary>
        /// <returns> valut address</returns>
        public string GetVaultAddress()
        {
            var tag = "-vault";
            string keyVaultVaultAddress = GetArgumentValue(tag);
            if (keyVaultVaultAddress == string.Empty)
            {
                keyVaultVaultAddress = ConfigurationManager.AppSettings["VaultUrl"];
                Console.Out.WriteLine(tag + " is not provided. Using default value: " + keyVaultVaultAddress);
            }
            return keyVaultVaultAddress;
        }

        /// <summary>
        /// Gets the setting to enable/disable tracing 
        /// </summary>
        /// <returns>true for enable, false for disable</returns>
        public bool GetTracingEnabled()
        {
            var value = ConfigurationManager.AppSettings["TracingEnabled"];
            bool enable = false;

            bool.TryParse(value, out enable);
            return enable;
        }

        /// <summary>
        /// Get key ID from argument list
        /// </summary>
        /// <returns> key ID </returns>
        public string GetKeyId()
        {
            var tag = "-keyid";
            string keyId = GetArgumentValue(tag);
            if (keyId == string.Empty)
            {
                throw new Exception(tag + " argument is missing");
            }
            return keyId;
        }

        /// <summary>
        /// Get key name from argument list
        /// </summary>
        /// <param name="mandatory"> whether the cli parameter is mandatory or not </param>
        /// <returns> the name of the key </returns>
        public string GetKeyName(bool mandatory = false, bool allowDefault = true)
        {
            var tag = "-keyname";
            string name = GetArgumentValue(tag);
            if (name == string.Empty)
            {
                if (mandatory == true)
                {
                    throw new Exception(tag + " argument is missing");
                }
                if (allowDefault)
                {
                    name = "mykey";
                    Console.Out.WriteLine(tag + " is not provided. Using default value: " + name);
                }
            }
            return name;
        }

        /// <summary>
        /// Get secret name from argument list
        /// </summary>
        /// <param name="mandatory"> whether the cli parameter is mandatory or not </param>
        /// <returns> the name of the secret </returns>
        public string GetSecretName(bool mandatory = false, bool allowDefault = true)
        {
            var tag = "-secretname";
            string name = GetArgumentValue(tag);

            if (name == string.Empty)
            {
                if (mandatory == true)
                {
                    throw new Exception(tag + " argument is missing");
                }
                if (allowDefault)
                {
                    name = "mysecret";
                    Console.Out.WriteLine(tag + " is not provided. Using default value: " + name);
                }
            }
            return name;
        }

        /// <summary>
        /// Get secret value from argument list
        /// </summary>
        /// <returns> the name of the secret </returns>
        public string GetSecretValue()
        {
            var tag = "-secretvalue";
            string value = GetArgumentValue(tag);
            if (value == string.Empty)
            {
                value = "default secret value";
                Console.Out.WriteLine(tag + " is not provided. Using new guid: " + value);
            }
            return value;
        }

        /// <summary>
        /// Get a set of key:value pairs to use as tags for keys/secrets
        /// </summary>
        /// <returns> dictionary to use as tags </returns>
        public Dictionary<string, string> GetTags()
        {
            return new Dictionary<string, string> { { "purpose", "demo Key Vault operations" }, { "app", "HelloKeyVault" } };
        }

        /// <summary>
        /// Get secret content type from argument list
        /// </summary>
        /// <returns> the content type of the secret </returns>
        public string GetSecretContentType()
        {
            var tag = "-secretcontenttype";
            string value = GetArgumentValue(tag);
            if (value == string.Empty)
            {
                value = "plaintext";
                Console.Out.WriteLine(tag + " is not provided. Using default value: " + value);
            }
            return value;
        }

        /// <summary>
        /// Get secret or key name from argument list
        /// </summary>
        /// <returns> secret name </returns>
        public string GetKeyVersion()
        {
            var tag = "-keyversion";
            string version = GetArgumentValue(tag);
            if (version == string.Empty)
            {
                Console.Out.WriteLine(tag + " is not provided.");
            }
            return version;
        }

        /// <summary>
        /// Get secret or key name from argument list
        /// </summary>
        /// <returns> secret name </returns>
        public string GetSecretVersion()
        {
            var tag = "-secretversion";
            string version = GetArgumentValue(tag);
            if (version == string.Empty)
            {
                Console.Out.WriteLine(tag + " is not provided.");
            }
            return version;
        }

        /// <summary>
        /// Get secret ID from argument list
        /// </summary>
        /// <returns> secret ID </returns>
        internal string GetSecretId()
        {
            var tag = "-secretid";
            string secretId = GetArgumentValue(tag);
            if (secretId == string.Empty)
            {
                throw new Exception(tag + " argument is missing");
            }
            return secretId;
        }

        /// <summary>
        /// Gets key bundle from args or uses a default key bundle
        /// </summary>
        /// <param name="args"> the input arguments of the console program </param>
        /// <returns> key bundle </returns>
        public KeyBundle GetKeyBundle()
        {
            // Default Key Bundle
            var defaultKeyBundle = new KeyBundle
            {
                Key = new JsonWebKey()
                {
                    Kty = GetKeyType(),
                },
                Attributes = new KeyAttributes()
                {
                    Enabled = true,
                    Expires = DateTime.MaxValue,
                    NotBefore = DateTime.Now
                }
            };

            return defaultKeyBundle;
        }

        internal string GetKeyType()
        {
            var tag = "-keytype";
            string keyType = GetArgumentValue(tag);
            if (keyType == string.Empty)
            {
                keyType = JsonWebKeyType.Rsa;
                Console.Out.WriteLine(tag + " is not provided. Selecting key type as: " + keyType);
            }
            return keyType;
        }

        /// <summary>
        /// Gets the import key bundle
        /// </summary>
        /// <returns> key bundle </returns>
        internal KeyBundle GetImportKeyBundle()
        {
            var rsa = new RSACryptoServiceProvider(2048);
            var webKey = CreateJsonWebKey(rsa.ExportParameters(true));

            // Default import Key Bundle
            var importKeyBundle = new KeyBundle
            {
                Key = webKey,
                Attributes = new KeyAttributes()
                {
                    Enabled = true,
                    Expires = DateTime.MaxValue,
                    NotBefore = DateTime.Now,
                }
            };

            return importKeyBundle;
        }

        /// <summary>
        /// Gets the update key attribute
        /// </summary>
        /// <returns> Key attribute to update </returns>
        internal KeyAttributes GetUpdateKeyAttribute()
        {
            return new KeyAttributes()
            {
                Enabled = true,
                Expires = DateTime.UtcNow.AddDays(2),
                NotBefore = DateTime.UtcNow.AddDays(-1)
            };
        }

        /// <summary>
        /// Gets the update key attribute
        /// </summary>
        /// <returns> Key attribute to update </returns>
        internal SecretAttributes GetSecretAttributes()
        {
            return new SecretAttributes()
            {
                Enabled = true,
                Expires = DateTime.UtcNow.AddYears(1),
                NotBefore = DateTime.UtcNow.AddDays(-1)
            };
        }

        /// <summary>
        /// Creates a random hash of type T
        /// </summary>
        /// <typeparam name="T"> a derived class from HashAlgorithm</typeparam>
        /// <param name="length"> the length of the hash code </param>
        /// <returns> hash code </returns>
        private static byte[] RandomHash<T>(int length)
        {
            var data = RandomBytes(length);
            var hash = (((T)Activator.CreateInstance(typeof(T))) as HashAlgorithm).ComputeHash(data);
            return hash;
        }

        /// <summary>
        /// Gets random bytes
        /// </summary>
        /// <param name="length"> the array length of the random bytes </param>
        /// <returns> array of random bytes </returns>
        private static byte[] RandomBytes(int length)
        {
            var bytes = new byte[length];
            Random rnd = new Random();
            rnd.NextBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// Gets the argument value according to the proceding key
        /// </summary>
        /// <param name="argTag"> arg tag</param>
        /// <returns> argument value </returns>
        private string GetArgumentValue(string argTag)
        {
            string result = string.Empty;
            for (int i = 0; i < args.Count(); i++)
            {
                if (string.Compare(args[i], argTag, true) == 0)
                {
                    if (i + 1 < args.Count())
                    {
                        result = args[i + 1];
                    }
                    break;
                }
            }
            return result;
        }

        /// <summary>
        /// Converts a RSAParameters object to a WebKey of type RSA.
        /// </summary>
        /// <param name="rsaParameters">The RSA parameters object to convert</param>
        /// <returns>A WebKey representing the RSA object</returns>
        private JsonWebKey CreateJsonWebKey(RSAParameters rsaParameters)
        {
            var key = new JsonWebKey
            {
                Kty = JsonWebKeyType.Rsa,
                E = rsaParameters.Exponent,
                N = rsaParameters.Modulus,
                D = rsaParameters.D,
                DP = rsaParameters.DP,
                DQ = rsaParameters.DQ,
                QI = rsaParameters.InverseQ,
                P = rsaParameters.P,
                Q = rsaParameters.Q
            };

            return key;
        }
    }

    public class InjectHostHeaderHttpMessageHandler : DelegatingHandler
    {
        /// <summary>
        /// Adds the Host header to every request if the "KmsNetworkUrl" configuration setting is specified.
        /// </summary>
        /// <param name="request"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestUri = request.RequestUri;
            var authority = string.Empty;
            var targetUri = requestUri;

            // NOTE: The KmsNetworkUrl setting is purely for development testing on the
            //       Microsoft Azure Development Fabric and should not be used outside that environment.
            string networkUrl = ConfigurationManager.AppSettings["KmsNetworkUrl"];

            if (!string.IsNullOrEmpty(networkUrl))
            {
                authority = targetUri.Authority;
                targetUri = new Uri(new Uri(networkUrl), targetUri.PathAndQuery);

                request.Headers.Add("Host", authority);
                request.RequestUri = targetUri;
            }

            return base.SendAsync(request, cancellationToken).ContinueWith<HttpResponseMessage>(response =>
            {
                return response.Result;
            });
        }
    }

    internal class ConsoleTracingInterceptor : ICloudTracingInterceptor
    {
        private void Write(string message, params object[] arguments)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            if (arguments == null || arguments.Length == 0)
            {
                Console.WriteLine(message);
            }
            else
            {
                Console.WriteLine(message, arguments);
            }
            Console.ResetColor();
        }
        public void Information(string message)
        {
            Write(message);
        }

        public void Configuration(string source, string name, string value)
        {
        }

        public void Enter(string invocationId, object instance, string method, IDictionary<string, object> parameters)
        {
            Write("{0} - [{1}]: Entered method {2} with arguments: {3}", invocationId, instance, method, parameters.AsFormattedString());
        }

        public void SendRequest(string invocationId, HttpRequestMessage request)
        {
            Write("{0} - {1}", invocationId, request.AsString());
        }

        public void ReceiveResponse(string invocationId, HttpResponseMessage response)
        {
            Write("{0} - {1}", invocationId, response.AsString());
        }

        public void Error(string invocationId, Exception ex)
        {
            Write("{0} - Error: {1}", invocationId, ex);
        }

        public void Exit(string invocationId, object result)
        {
            Write("{0} - Exited method with result: {1}", invocationId, result);
        }
    }
}