﻿// Program.cs
// CSCI251 - Project 3
// July 15, 2022
// Summer DiStefano (srd3629@rit.edu)
//
// Main file that runs the Messenger program.

using System;
using System.ComponentModel.DataAnnotations;

namespace Messenger
{
    public class Program
    {
        // Prints a given error message for when the command line arguments are invalid.
        //
        // param 'message': Error message to be printed
        private static void PrintErrorMessage(string message)
        {
            Console.Write
            (
                "\nERROR: " + message + " See usage message below.\n" +
                "USAGE: dotnet run <option> <other arguments>\n" +
                "Following are the valid options with their corresponding arguments:\n" +
                String.Format("{0, 21}{1, 14} {2}", new object[]{"- keyGen <key size>", "==>", "Generate a key-pair of size 'key size' bits. Minimum: 32 bits.\n"}) +
                String.Format("{0, 19}{1, 16} {2}", new object[]{"- sendKey <email>", "==>", "Send the public key generated by keyGen to the server, with the email address given.\n"}) +
                String.Format("{0, 18}{1, 17} {2}", new object[]{"- getKey <email>", "==>", "Get public key for a particular user, identified by their email address.\n"}) +
                String.Format("{0, 29}{1, 6} {2}", new object[]{"- sendMsg <email> <message>", "==>", "Sends the given message to the person with the given email address.\n"}) +
                String.Format("{0, 18}{1, 17} {2}", new object[]{"- getMsg <email>", "==>", "Retrieve a message for the user with the given email address.\n\n"})
            );
        }


        // Runs the program.
        //
        // param 'args': Command line arguments
        public static void Main(string[] args)
        {
            if (args.Length == 2)
            {
                if (args[0] == "keyGen")
                {
                    int keySize;
                    if (!int.TryParse(args[1], out keySize))
                    { 
                        PrintErrorMessage("Key size must be an integer.");
                        return;
                    }
                    if (keySize < 32)
                    {
                        PrintErrorMessage("Key size must be greater than 32 bits.");
                        return;
                    }
                    KeyHandler.GenerateKey(keySize);
                }
                else
                {
                    var isEmailValid = new EmailAddressAttribute().IsValid(args[1]);
                    switch(args[0])
                    {
                        case "sendKey":
                            if (isEmailValid) KeyHandler.SendKey(args[1]);
                            break;
                        case "getKey":
                            if (isEmailValid) KeyHandler.GetKey(args[1]);
                            break;
                        case "getMsg":
                            if (isEmailValid) MessageHandler.GetMessage(args[1]);
                            break;
                        default:
                            PrintErrorMessage("Argument '" + args[0] + "' is invalid.");
                            return;
                    }
                    if (!isEmailValid) PrintErrorMessage("Provided email address has incorrect format.");
                }
            }
            else if (args.Length == 3)
            {
                if (args[0] != "sendMsg")
                {
                    PrintErrorMessage("Either argument '" + args[0] + "' is invalid or incorrect number of arguments provided.");
                    return;
                }
                var isEmailValid = new EmailAddressAttribute().IsValid(args[1]);
                if (!isEmailValid)
                {
                    PrintErrorMessage("Provided email address has incorrect format.");
                    return;
                }
                MessageHandler.SendMessage(args[1], args[2]);
            }
            else
            {
                PrintErrorMessage("Incorrect number of command line arguments provided.");
            }
        }
    }
}