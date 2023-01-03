// Keys.cs
// CSCI251 - Project 3
// July 15, 2022
// Summer DiStefano (srd3629@rit.edu)
//
// This file holds the public and private key objects, as well as the methods used to generate, decode, send,
// and retrieve public and private keys.

using System;
using System.Numerics;
using System.Net.Http;
using System.Text;
using Newtonsoft.Json;

namespace Messenger
{
    // Object representing a private key. Holds a base64-encoded string as its key and a list of email addresses
    // associated with it.
    public class PrivateKey
    {
        public List<string>? email { get; set; }
        public string? key { get; set; }
    }


    // Object representing a public key. Holds a base64-encoded string as its key and the email address associated
    // with it.
    public class PublicKey
    {
        public string? email { get; set; }
        public string? key { get; set; }
    }


    // Class that holds methods for generating, decoding, sending, and retrieving public and private keys.
    public static class KeyHandler
    {
        // Base URL for sending and receiving public keys from the server.
        private static readonly string keyUrl = "http://kayrun.cs.rit.edu:5000/Key/";

        // Client used for 'get' and 'put' tasks.
        private static readonly HttpClient httpClient = new HttpClient();


        // Uses the RSA algorithm to generate a public key and private key, both of the given bit size, and stores
        // them in files called 'public.key' and 'private.key', respectively.
        //
        // param 'keySize': The bit size of the keys to be generated
        public static void GenerateKey(int keySize) 
        {
            // Generate bit sizes for p and q.
            var sizeOfP = (int)Math.Ceiling(keySize * 0.7);
            var sizeOfQ = (int)keySize - sizeOfP;
            // Generate two random prime numbers to be p and q.
            var p = PrimeGenerator.GeneratePrime(sizeOfP);
            var q = PrimeGenerator.GeneratePrime(sizeOfQ);
            // Generate rest of variables.
            var E = new BigInteger(65537);
            var N = p * q;
            var r = (p - 1) * (q - 1);
            var D = ModInverse(E, r);
            // Public key = (E, N)
            var sizeOfE = ConvertSizeToByteArray(E.GetByteCount());
            var sizeOfN = ConvertSizeToByteArray(N.GetByteCount());
            var publicKeyBytes = new byte[8 + E.GetByteCount() + N.GetByteCount()];
            sizeOfE.CopyTo(publicKeyBytes, 0);
            E.ToByteArray().CopyTo(publicKeyBytes, 4);
            sizeOfN.CopyTo(publicKeyBytes, 4 + E.GetByteCount());
            N.ToByteArray().CopyTo(publicKeyBytes, 8 + E.GetByteCount());
            // Private key = (D, N)
            var sizeOfD = ConvertSizeToByteArray(D.GetByteCount());
            var privateKeyBytes = new byte[8 + D.GetByteCount() + N.GetByteCount()];
            sizeOfD.CopyTo(privateKeyBytes, 0);
            D.ToByteArray().CopyTo(privateKeyBytes, 4);
            sizeOfN.CopyTo(privateKeyBytes, 4 + D.GetByteCount());
            N.ToByteArray().CopyTo(privateKeyBytes, 8 + D.GetByteCount());
            // Base64 encode keys to strings and create new key objects.
            var publicKey = new PublicKey(){ email = null, key = Convert.ToBase64String(publicKeyBytes)};
            var privateKey = new PrivateKey(){ email = null, key = Convert.ToBase64String(privateKeyBytes)};
            // Write keys to files.
            File.WriteAllText("public.key", JsonConvert.SerializeObject(publicKey));
            File.WriteAllText("private.key", JsonConvert.SerializeObject(privateKey));
        }


        // Helper function used to calculate the mod-inverse of a BigInteger value. Parameters are variables in
        // the RSA algorithm.
        //
        // param 'E': Number to find the mod-inverse of (a prime number)
        // param 'r': From RSA, r = (p - 1) * (q - 1)
        //
        // return: BigInteger representing the mod-inverse of E
        private static BigInteger ModInverse(BigInteger E, BigInteger r)
        {
            BigInteger i = r, v = 0, d = 1;
            while (E > 0) 
            {
                BigInteger t = i / E, x = E;
                E = i % x;
                i = x;
                x = d;
                d = v - (t * x);
                v = x;
            }
            v %= r;
            if (v < 0) v = (v + r) % r;
            return v;
        }


        // Helper function to convert an integer, representing the size of a value, into a four-element byte array.
        // (E.g., 4 => [0, 0, 0, 4]; 127 => [0, 1, 2, 7])
        //
        // param 'size': Integer value to convert
        //
        // return: Resulting four-element byte array
        private static byte[] ConvertSizeToByteArray(int size)
        {
            var sizeString = size.ToString();
            var numZerosNeeded = 4 - sizeString.Length;
            var byteArray = new byte[4];
            for (int i = numZerosNeeded; i < 4; ++i) 
                byteArray.SetValue(Convert.ToByte(sizeString.Substring(i - numZerosNeeded, 1)), i);
            return byteArray;
        }


        // Takes the previously generated public and private keys from files 'public.key' and 'private.key',
        // associates the given email address to them, and sends the public key to the server.
        //
        // param 'emailAddress': The email address to associate with the public and private keys
        public static void SendKey(string emailAddress) 
        {
            // Check if public and private key files exist.
            if (!File.Exists("public.key") || !File.Exists("private.key"))
            {
                Console.WriteLine("ERROR: Public and private keys must be generated before they can be sent.\n");
                return;
            }
            // Get public and private key objects.
            var publicKey = JsonConvert.DeserializeObject<PublicKey>(File.ReadAllText("public.key"));
            var privateKey = JsonConvert.DeserializeObject<PrivateKey>(File.ReadAllText("private.key"));
            if (privateKey == null || privateKey.key == null || publicKey == null || publicKey.key == null)
            {
                Console.WriteLine("ERROR: Public and private keys must be generated before they can be sent.\n");
                return;
            }
            // Add email address to public and private keys.
            publicKey.email = emailAddress;
            if (privateKey.email == null) 
            {
                privateKey.email = new List<string>(){ emailAddress };
            }
            else
            {
                privateKey.email.Add(emailAddress);
            }
            // Save email address in private key file.
            File.WriteAllText("private.key", JsonConvert.SerializeObject(privateKey));
            // Send public key to server.
            var url = keyUrl + emailAddress;
            try
            {
                var httpContent = new StringContent(JsonConvert.SerializeObject(publicKey), Encoding.UTF8, "application/json");
                Task<HttpResponseMessage> putTask = httpClient.PutAsync(url, httpContent);
                putTask.Wait();
                putTask.Result.EnsureSuccessStatusCode();
                Console.WriteLine("Key saved\n");
            }
            catch (Exception)
            {
                Console.WriteLine("ERROR: Could not save public key to server.\n");
            }
        }


        // Gets the public key associated with the given email address from the server, and saves it to a file
        // titled with the format '{email Address}.key'.
        //
        // param 'emailAddress': The email address for which to retrieve the public key
        public static async void GetKey(string emailAddress) {
            var url = keyUrl + emailAddress;
            try
            {   // Get public key info from the server.
                Task<HttpResponseMessage> getTask = httpClient.GetAsync(url);
                getTask.Wait();
                HttpResponseMessage response = getTask.Result;
                response.EnsureSuccessStatusCode();
                var responseJsonString = await response.Content.ReadAsStringAsync();
                if (responseJsonString == null || responseJsonString == "") throw new Exception();
                var newFileName = emailAddress + ".key";
                File.WriteAllText(newFileName, responseJsonString);
            }
            catch (Exception)
            {
                Console.WriteLine("ERROR: Could not get public key from server.\n");
            }
        }


        // Method used to determine the E and N values from a public key, or the D and N values from a private key.
        // Takes the key JSON from the given key file and deserializes it, base64-decodes it, and determines the
        // values.
        //
        // param 'keyFile': File containing the key to decode
        // param 'keyType': String indicating if the key will be public or private. (I.e., "public" or "private")
        //
        // return: List containing BigInteger values E and N (for public key), or D and N (for private key)
        public static IEnumerable<BigInteger> DecodeKey(string keyFile, string keyType)
        {
            byte[]? bytes = null;
            // Get json string and deserialize it into a key object. Base64 decode 'key' part of key object to byte array.
            if (keyType == "public")
            {
                var publicKey = JsonConvert.DeserializeObject<PublicKey>(File.ReadAllText(keyFile));
                if (publicKey != null && publicKey.key != null) bytes = Convert.FromBase64String(publicKey.key);
            }
            else if (keyType == "private")
            {
                var privateKey = JsonConvert.DeserializeObject<PrivateKey>(File.ReadAllText(keyFile));
                if (privateKey != null && privateKey.key != null) bytes = Convert.FromBase64String(privateKey.key);
            }
            if (bytes != null && bytes.Length > 0)
            {
                // Determine e, E, n, and N. If private key, D is E.
                var e = ConvertByteSizeToInt(bytes.Take(4).ToArray());
                var E = new BigInteger(bytes.Skip(4).Take(e).ToArray());
                var n = ConvertByteSizeToInt(bytes.Skip(4 + e).Take(4).ToArray());
                var N = new BigInteger(bytes.Skip(8 + e).Take(n).ToArray());
                return new List<BigInteger>(){ E, N };
            }
            return new List<BigInteger>();
        }


        // Helper function to convert a byte array, representing the size of a value, into an integer.
        // (E.g., [0, 1, 2, 7] => 127)
        //
        // param 'byteSize': Byte array to convert
        //
        // return: Resulting integer value
        private static int ConvertByteSizeToInt(byte[] byteSize)
        {
            var intBuilder = new StringBuilder();
            foreach (var b in byteSize) intBuilder.Append(b);
            return Int32.Parse(intBuilder.ToString());
        }
    }
}