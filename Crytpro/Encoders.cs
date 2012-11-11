using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptpro
{
	public static class Encrypters
    {
		public static byte[] CaesarEncrypt(byte[] input, byte key)
		{
			byte[] output = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				unchecked
				{
					output[i] = (byte)(input[i] + key);
				}
			}
			return output;
		}
		public static byte[] CaesarDecrypt(byte[] input, byte key)
		{
			byte[] output = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				unchecked
				{
					output[i] = (byte)(input[i] - key);
				}
			}
			return output;
		}

		public static byte[] ScramblerEncrypt(byte[] input, byte[] key)
		{
			byte[] output = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				unchecked
				{
					output[i] = (byte)(input[i] ^ key[i % key.Length]);
				}
			}
			return output;
		}

		public static byte[] ScramblerDecrypt(byte[] input, byte[] key)
		{
			byte[] output = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				unchecked
				{
					output[i] = (byte)(input[i] ^ key[i % key.Length]);
				}
			}
			return output;
		}
    }
}
