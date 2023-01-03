// PrimeGenerator.cs
// CSCI251 - Project 3
// July 15, 2022
// Summer DiStefano (srd3629@rit.edu)
//
// File for PrimeGenerator class. PrimeGenerator creates random BigInteger values of a given bit-size and continues
// until it finds and returns a prime number.

using System;
using System.Security.Cryptography;
using System.Numerics;

namespace Messenger
{
    public static class PrimeGenerator
    {
        // Generates random numbers of a given bit-size until a prime number is found. Returns that prime number.
        //
        // param 'numBits': Desired bit-size for the prime number
        //
        // return: A prime BigInteger value
        public static BigInteger GeneratePrime(int numBits)
        {
            BigInteger randomNum;
            do
            {
                randomNum = BigInteger.Abs(new BigInteger(RandomNumberGenerator.GetBytes(numBits / 8)));
            }
            while (!randomNum.IsProbablyPrime());
            return randomNum;
        }


        // Uses the Miller-Rabin Primality Test to determine if a given number is likely prime.
        //
        // param 'value': BigInteger number to be checked for primality
        // param 'k': Number of rounds of testing to perform
        //
        // return: True if value is probably prime, false if it's composite
        public static Boolean IsProbablyPrime(this BigInteger value, int k = 10)
        {
            if (k <= 0) k = 10;
            var basicPrimes = new List<int>() { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 
                47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 };
            foreach (var prime in basicPrimes)
            {
                if (value.Equals(prime)) return true;
            }
            if (value.IsEven || value.IsPowerOfTwo)
            {
                return false;
            }
            else
            {
                // Get the 'd' and 'r' values.
                var d = value - 1;
                var r = 0;
                while (d.IsEven)
                {
                    d /= 2;
                    r += 1;
                }
                for (var i = 0; i < k; ++i)
                {
                    // Get random BigInteger 'a' in range (2, value - 2).
                    var random = new Random();
                    Byte[] bytes = new Byte[value.ToByteArray().Length];
                    random.NextBytes(bytes);
                    var a = new BigInteger(bytes);
                    if (a < 2 || a > value - 2) a = 2 + BigInteger.Abs(a) % ((value - 2) - 2); 
                    // Run the rest.
                    var x = BigInteger.ModPow(a, d, value);
                    if (x == 1 || x == value - 1) continue;
                    for (var j = 0; j < r - 1; ++j)
                    {
                        x = BigInteger.ModPow(x, 2, value);
                        if (x == 1) return false;
                        if (x == value - 1) break;
                    }
                    if (x != value - 1) return false;     // It's composite.
                }
                return true;    // It's probably prime.
            }
        }
    }
}