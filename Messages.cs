// Messages.cs
// CSCI251 - Project 3
// July 15, 2022
// Summer DiStefano (srd3629@rit.edu)
//
// This file holds the Message object, and methods for sending and receiving messages from the server.

using System;
using System.Numerics;
using System.Net.Http;
using System.Text;
using Newtonsoft.Json;

namespace Messenger
{
    // Object representing a message. Holds the email of the user the message is meant for and the message's content.
    public class Message
    {
        public string? email { get; set; }
        public string? content { get; set; }
    }


    // Class that holds the methods for sending and receiving messages from the server.
    public static class MessageHandler
    {
        // Base URL for sending and receiving messages from the server.
        private static readonly string messageUrl = "http://kayrun.cs.rit.edu:5000/Message/";

        // Client used for 'get' and 'put' tasks.
        private static readonly HttpClient httpClient = new HttpClient();


        // Sends an encrypted message to the server for the user with the given email address. Must have a public key
        // saved for that email address in order to encrypt the message.
        //
        // param 'emailAddress': Email address of the user we want to send the message to
        // param 'message': The message to send
        public static void SendMessage(string emailAddress, string message) 
        {
            // Check if we have the public key for the given email address.
            if (!File.Exists(emailAddress + ".key"))
            {
                Console.WriteLine("Key does not exist for " + emailAddress + "\n");
                return;
            }
            // Get the public key and decode it.
            var encryptValues = KeyHandler.DecodeKey(emailAddress + ".key", "public");     // = [E, N]
            // Encrypt the message.
            var messageBigInt = new BigInteger(Encoding.UTF8.GetBytes(message));
            var encryption = BigInteger.ModPow(messageBigInt, encryptValues.ElementAt(0), encryptValues.ElementAt(1));
            var cipherText = Convert.ToBase64String(encryption.ToByteArray());
            // Load message into message object.
            var messageObject = new Message(){ email = emailAddress, content = cipherText };
            // Send message to server.
            var url = messageUrl + emailAddress;
            try
            {
                var httpContent = new StringContent(JsonConvert.SerializeObject(messageObject), Encoding.UTF8, "application/json");
                Task<HttpResponseMessage> putTask = httpClient.PutAsync(url, httpContent);
                putTask.Wait();
                putTask.Result.EnsureSuccessStatusCode();
                Console.WriteLine("Message written\n");
            }
            catch (Exception)
            {
                Console.WriteLine("ERROR: Could not send message to server.\n");
            }
        }


        // Retrieves an encrypted message for the user with the given email address and decrypts it. Must have a
        // private key saved for that email address in order to decrypt the message.
        //
        // param 'emailAddress': Email address of the user the message is intended for
        public static async void GetMessage(string emailAddress)
        {
            // Check if we have a private key saved.
            if (!File.Exists("private.key"))
            {
                Console.WriteLine("ERROR: Message cannot be decoded.\n");
                return;
            }
            // Get saved private key.
            var privateKey = JsonConvert.DeserializeObject<PrivateKey>(File.ReadAllText("private.key"));
            if (privateKey == null || privateKey.key == null || privateKey.email == null 
                || privateKey.email.Count == 0 || !privateKey.email.Contains(emailAddress))
            {
                Console.WriteLine("ERROR: Message cannot be decoded.\n");
                return;
            }
            // Get message from server.
            var url = messageUrl + emailAddress;
            try
            {
                Task<HttpResponseMessage> getTask = httpClient.GetAsync(url);
                getTask.Wait();
                HttpResponseMessage response = getTask.Result;
                response.EnsureSuccessStatusCode();
                var responseJsonString = await response.Content.ReadAsStringAsync();
                var messageObject = JsonConvert.DeserializeObject<Message>(responseJsonString);
                if (messageObject == null || messageObject.content == null) throw new Exception();
                var messageBigInt = new BigInteger(Convert.FromBase64String(messageObject.content));
                // Decrypt and print the message.
                var decryptValues = KeyHandler.DecodeKey("private.key", "private");    // = [D, N]
                var decryption = BigInteger.ModPow(messageBigInt, decryptValues.ElementAt(0), decryptValues.ElementAt(1));
                var message = Encoding.ASCII.GetString(decryption.ToByteArray());
                Console.WriteLine(message + "\n");
            }
            catch (Exception)
            {
                Console.WriteLine("ERROR: Could not get message from server.\n");
            }
        }
    }
}