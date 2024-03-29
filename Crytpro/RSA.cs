﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Numerics;
namespace Cryptpro
{
	public static class RSA
	{
		public static void Encrypt()
		{
			BigInteger i = new BigInteger(5);
		}

		public static KeyPair Generate(int length)
		{
			KeyPair pair = new KeyPair();
			int byteLength = length / 8;
			BigInteger p = new BigInteger(Random(byteLength / 2));
			BigInteger q = new BigInteger(Random(byteLength / 2));
			pair.N = (q - 1) * (p - 1);
			pair.E = 3;
			while (BigInteger.GreatestCommonDivisor(pair.E, pair.N) > 1)
			{
				pair.E += 2;
			}
			pair.D = 12;
			return pair;
		}

		static byte[] Random(int length)
		{
			Random r = new Random();
			byte[] result = new byte[length];
			r.NextBytes(result);
			return result;
		}

		public class KeyPair
		{
			public BigInteger N { get; set; }
			public BigInteger E { get; set; }
			public BigInteger D { get; set; }
		}

		public static byte[] Encrypt(byte[] input, BigInteger N, BigInteger E)
		{
			int originalsize = input.Length;
			int inputBlockLength = N.ToByteArray().Length - 1;
			int encodedBlockLength = inputBlockLength + 1;
			int blocksCount = input.Length / inputBlockLength;
			if (input.Length % inputBlockLength != 0)
			{
				blocksCount++;
				Array.Resize(ref input, blocksCount * inputBlockLength);
			}
			int headerSize = 4;
			byte[] encodedResult = new byte[blocksCount * encodedBlockLength + headerSize];
			Array.Copy(BitConverter.GetBytes(originalsize), encodedResult, 4);
			for (int i = 0; i < (input.Length / inputBlockLength) + 1; i++)
			{
				byte[] block = new byte[inputBlockLength];
				Array.Copy(input, i + inputBlockLength, block, 0, inputBlockLength);
				BigInteger message = new BigInteger(block);
				byte[] bytes = BigInteger.ModPow(message, E, N).ToByteArray();
				Array.Copy(bytes, 0, encodedResult, headerSize + i * encodedBlockLength, bytes.Length);
			}


			return encodedResult;
		}


		public static byte[] Decrypt(byte[] input, BigInteger N, BigInteger E)
		{
			int originalsize = input.Length;
			int inputBlockLength = N.ToByteArray().Length - 1;
			int encodedBlockLength = inputBlockLength + 1;
			int blocksCount = input.Length / inputBlockLength;
			if (input.Length % inputBlockLength != 0)
			{
				blocksCount++;
				Array.Resize(ref input, blocksCount * inputBlockLength);
			}
			int headerSize = 4;
			byte[] encodedResult = new byte[blocksCount * encodedBlockLength + headerSize];
			Array.Copy(BitConverter.GetBytes(originalsize), encodedResult, 4);
			for (int i = 0; i < (input.Length / inputBlockLength) + 1; i++)
			{
				byte[] block = new byte[inputBlockLength];
				Array.Copy(input, i + inputBlockLength, block, 0, inputBlockLength);
				BigInteger message = new BigInteger(block);
				byte[] bytes = BigInteger.ModPow(message, E, N).ToByteArray();
				Array.Copy(bytes, 0, encodedResult, headerSize + i * encodedBlockLength, bytes.Length);
			}

			return encodedResult;
		}

		private static BigInteger ModInverse(BigInteger a, BigInteger b)
		{
			BigInteger dividend = a % b;
			BigInteger divisor = b;

			BigInteger last_x = BigInteger.One;
			BigInteger curr_x = BigInteger.Zero;

			while (divisor.Sign > 0)
			{
				BigInteger quotient = dividend / divisor;
				BigInteger remainder = dividend % divisor;
				if (remainder.Sign <= 0)
				{
					break;
				}

				/* This is quite clever, in the algorithm in form
				 * ax + by = gcd(a, b) we only keep track of the
				 * value curr_x and the last_x from last iteration,
				 * the y value is ignored anyway. After remainder
				 * runs to zero, we get our inverse from curr_x */
				BigInteger next_x = last_x - curr_x * quotient;
				last_x = curr_x;
				curr_x = next_x;

				dividend = divisor;
				divisor = remainder;
			}

			if (divisor != BigInteger.One)
			{
				throw new Exception("Numbers a and b are not relatively primes");
			}
			return (curr_x.Sign < 0 ? curr_x + b : curr_x);
		}
	}
}
