using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptpro
{
	public class DESCrypto
	{
		// initial permuation table
		private static int[] initialPermitation = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36,
			28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32,
			24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19,
			11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
		// inverse initial permutation
		private static int[] initialPermitationInverse = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47,
			15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13,
			53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51,
			19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

		// Permutation P (in f(Feistel) function)
		private static int[] feisterPermutation = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5,
			18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

		// initial key permutation 64 => 56 bit
		private static int[] keyTo56 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34,
			26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63,
			55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53,
			45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };

		// key permutation at round i 56 => 48
		private static int[] keyTo48 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29,	32 };

		// key shift for each round
		private static int[] keyShift = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

		// expansion permutation from function f
		private static int[] expandTable = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8,
			9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,
			1 };

		// substitution boxes
		private static int[, ,] sBoxesTable = {
			{ 		{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
					{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
					{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
					{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } 
			},
			{ 		{ 15, 1, 8, 14, 6, 11, 3, 2, 9, 7, 2, 13, 12, 0, 5, 10 },
					{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
					{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
					{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } 
			},
			{ 		{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
					{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
					{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
					{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } 
			},
			{ 		{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
					{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
					{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
					{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } 
			},
			{ 		{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
					{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
					{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
					{ 11, 8, 12, 7, 1, 14, 2, 12, 6, 15, 0, 9, 10, 4, 5, 3 } 
			},
			{ 		{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
					{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
					{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
					{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }

			},
			{ 		{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
					{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
					{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
					{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }

			},
			{ 		{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
					{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
					{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
					{ 2, 1, 14, 7, 4, 10, 18, 13, 15, 12, 9, 0, 3, 5, 6, 11 }

			} };

		public static byte[] Encrypt(byte[] data, byte[] key)
		{
			int length = 0;
			byte[] padding = new byte[1];
			int i;
			length = 8 - data.Length % 8;
			padding = new byte[length];
			padding[0] = (byte)0x80;

			for (i = 1; i < length; i++)
				padding[i] = 0;

			byte[] tmp = new byte[data.Length + length];
			byte[] block = new byte[8];

			byte[][] K = GenerateSubKeys(key);

			int count = 0;

			for (i = 0; i < data.Length + length; i++)
			{
				if (i > 0 && i % 8 == 0)
				{
					block = Encrypt64(block, K, false);
					Array.ConstrainedCopy(block, 0, tmp, i - 8, block.Length);
				}
				if (i < data.Length)
					block[i % 8] = data[i];
				else
				{
					block[i % 8] = padding[count % 8];
					count++;
				}
			}
			if (block.Length == 8)
			{
				block = Encrypt64(block, K, false);
				Array.ConstrainedCopy(block, 0, tmp, i - 8, block.Length);
			}
			return tmp;
		}

		public static byte[] Decrypt(byte[] data, byte[] key)
		{
			int i;
			byte[] tmp = new byte[data.Length];
			byte[] block = new byte[8];

			byte[][] K = GenerateSubKeys(key);

			for (i = 0; i < data.Length; i++)
			{
				if (i > 0 && i % 8 == 0)
				{
					block = Encrypt64(block, K, true);
					Array.ConstrainedCopy(block, 0, tmp, i - 8, block.Length);
				}
				if (i < data.Length)
					block[i % 8] = data[i];
			}
			block = Encrypt64(block, K, true);
			Array.ConstrainedCopy(block, 0, tmp, i - 8, block.Length);


			tmp = DeletePadding(tmp);

			return tmp;
		}

		private static void SetBit(byte[] data, int pos, byte val)
		{
			int posByte = pos / 8;
			int posBit = pos % 8;
			byte tmpB = data[posByte];
			tmpB = (byte)(((0xFF7F >> posBit) & tmpB) & 0x00FF);
			byte newByte = (byte)((val << (8 - (posBit + 1))) | tmpB);
			data[posByte] = newByte;
		}

		private static byte ExtractBit(byte[] data, int pos)
		{
			int posByte = pos / 8;
			int posBit = pos % 8;
			byte tmpB = data[posByte];
			byte bit = (byte)(tmpB >> (8 - (posBit + 1)) & 0x0001);
			return bit;
		}

		private static byte[] ShiftLeft(byte[] input, int len, int pas)
		{
			byte[] output = new byte[(len - 1) / 8 + 1];
			for (int i = 0; i < len; i++)
			{
				byte val = ExtractBit(input, (i + pas) % len);
				SetBit(output, i, val);
			}
			return output;
		}

		private static byte[] ExtractBits(byte[] input, int pos, int n)
		{
			byte[] output = new byte[(n - 1) / 8 + 1];
			for (int i = 0; i < n; i++)
			{
				byte val = ExtractBit(input, pos + i);
				SetBit(output, i, val);
			}
			return output;

		}

		private static byte[] Permutate(byte[] input, int[] table)
		{
			byte[] output = new byte[(table.Length - 1) / 8 + 1];
			for (int i = 0; i < table.Length; i++)
			{
				byte bit = ExtractBit(input, table[i] - 1);
				SetBit(output, i, bit);
			}
			return output;

		}

		private static byte[] Xor(byte[] a, byte[] b)
		{
			byte[] output = new byte[a.Length];
			for (int i = 0; i < a.Length; i++)
			{
				output[i] = (byte)(a[i] ^ b[i]);
			}
			return output;

		}

		private static byte[] Encrypt64(byte[] block, byte[][] subkeys, bool isDecrypt)
		{
			byte[] tmp = new byte[block.Length];
			byte[] R = new byte[block.Length / 2];
			byte[] L = new byte[block.Length / 2];

			tmp = Permutate(block, initialPermitation);

			L = ExtractBits(tmp, 0, initialPermitation.Length / 2);
			R = ExtractBits(tmp, initialPermitation.Length / 2, initialPermitation.Length / 2);

			for (int i = 0; i < 16; i++)
			{
				byte[] tmpR = R;
				if (isDecrypt)
					R = FDistortion(R, subkeys[15 - i]);
				else
					R = FDistortion(R, subkeys[i]);
				R = Xor(L, R);
				L = tmpR;
			}

			tmp = ConcatBits(R, initialPermitation.Length / 2, L, initialPermitation.Length / 2);

			tmp = Permutate(tmp, initialPermitationInverse);
			return tmp;
		}

		private static byte[] FDistortion(byte[] R, byte[] K)
		{
			byte[] tmp;
			tmp = Permutate(R, expandTable);
			tmp = Xor(tmp, K);
			tmp = SDistortion(tmp);
			tmp = Permutate(tmp, feisterPermutation);
			return tmp;
		}

		private static byte[] SDistortion(byte[] input)
		{
			input = SeparateBytes(input, 6);
			byte[] output = new byte[input.Length / 2];
			int halfByte = 0;
			for (int b = 0; b < input.Length; b++)
			{
				byte valByte = input[b];
				int r = 2 * (valByte >> 7 & 0x0001) + (valByte >> 2 & 0x0001);
				int c = valByte >> 3 & 0x000F;
				int val = sBoxesTable[b, r, c];
				if (b % 2 == 0)
					halfByte = val;
				else
					output[b / 2] = (byte)(16 * halfByte + val);
			}
			return output;
		}

		private static byte[] SeparateBytes(byte[] input, int len)
		{
			int numOfBytes = (8 * input.Length - 1) / len + 1;
			byte[] output = new byte[numOfBytes];
			for (int i = 0; i < numOfBytes; i++)
			{
				for (int j = 0; j < len; j++)
				{
					byte val = ExtractBit(input, len * i + j);
					SetBit(output, 8 * i + j, val);
				}
			}
			return output;
		}

		private static byte[] ConcatBits(byte[] a, int aLen, byte[] b, int bLen)
		{
			int numOfBytes = (aLen + bLen - 1) / 8 + 1;
			byte[] output = new byte[numOfBytes];
			int j = 0;
			for (int i = 0; i < aLen; i++)
			{
				byte val = ExtractBit(a, i);
				SetBit(output, j, val);
				j++;
			}
			for (int i = 0; i < bLen; i++)
			{
				byte val = ExtractBit(b, i);
				SetBit(output, j, val);
				j++;
			}
			return output;
		}

		private static byte[] DeletePadding(byte[] input)
		{
			int count = 0;

			int i = input.Length - 1;
			while (input[i] == 0)
			{
				count++;
				i--;
			}

			byte[] tmp = new byte[input.Length - count - 1];
			Array.ConstrainedCopy(input, 0, tmp, 0, tmp.Length);
			return tmp;
		}

		private static byte[][] GenerateSubKeys(byte[] key)
		{
			byte[][] tmp = new byte[16][];
			byte[] tmpK = Permutate(key, keyTo56);

			byte[] C = ExtractBits(tmpK, 0, keyTo56.Length / 2);
			byte[] D = ExtractBits(tmpK, keyTo56.Length / 2, keyTo56.Length / 2);

			for (int i = 0; i < 16; i++)
			{

				C = ShiftLeft(C, 28, keyShift[i]);
				D = ShiftLeft(D, 28, keyShift[i]);

				byte[] cd = ConcatBits(C, 28, D, 28);

				tmp[i] = Permutate(cd, keyTo48);
			}

			return tmp;
		}

	}

}
