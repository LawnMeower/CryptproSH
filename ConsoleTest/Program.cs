using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptpro;
namespace ConsoleTest
{
	class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("Please, enter string to encode:");
			string input = Console.ReadLine();

			Console.WriteLine("Enter caesar shift:");
			byte caesarKey = (byte)(int.Parse(Console.ReadLine()) % 256);

			byte[] bytes = Encoding.ASCII.GetBytes(input);

			byte[] scramblerKey = { 125, 0, 14, 39, 248, 14, 96, 251, 98 };

			byte[] key = { 125, 0, 14, 39, 248, 14, 96, 251};
						
			byte[] encrypted = Encrypters.CaesarEncrypt(bytes, caesarKey);

			Console.WriteLine("Encrypted Caesar: {0}", Encoding.ASCII.GetString(encrypted));

			byte[] decrypted = Encrypters.CaesarDecrypt(encrypted, caesarKey);

			Console.WriteLine("Decrypted Caesar: {0}", Encoding.ASCII.GetString(decrypted));

			encrypted = Encrypters.ScramblerEncrypt(bytes, scramblerKey);

			Console.WriteLine("Encrypted Scrambler: {0}", Encoding.ASCII.GetString(encrypted));

			decrypted = Encrypters.ScramblerDecrypt(encrypted, scramblerKey);

			Console.WriteLine("Decrypted Scrambler: {0}", Encoding.ASCII.GetString(decrypted));

			encrypted = DESCrypto.Encrypt(bytes, key);

			Console.WriteLine("Encrypted Des: {0}", Encoding.ASCII.GetString(encrypted));

			decrypted = DESCrypto.Decrypt(encrypted, key);

			Console.WriteLine("Decrypted Des: {0}", Encoding.ASCII.GetString(decrypted));

			Console.ReadKey();

		}
	}
}
