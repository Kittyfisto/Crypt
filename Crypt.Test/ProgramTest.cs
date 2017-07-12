using System;
using System.IO;
using System.Linq;
using System.Text;
using FluentAssertions;
using NUnit.Framework;

namespace Crypt.Test
{
	[TestFixture]
	public class ProgramTest
	{
		[Test]
		public void TestEncryptDecrypt1()
		{
			const string secret = "Hello, World!";
			const string password = "secret";
			const int iterations = 123;
			var salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
			byte[] key;
			byte[] iv;
			Program.GenerateKeyAndInitializationVector(password, salt, iterations, 256, 128, out key, out iv);

			using (var source = new MemoryStream())
			using (var dest = new MemoryStream())
			{
				using (var sourceWriter = new StreamWriter(source, Encoding.UTF8, 1024, true))
				{
					Console.WriteLine("Secret: {0}", secret);
					sourceWriter.Write(secret);
				}

				source.Position = 0;
				Program.Encrypt(source, dest, key, iv);

				Console.WriteLine("Encrypted secret: {0}", string.Join(", ", dest.ToArray().Select(i => string.Format("0x{0:X}", i))));

				using (var decrypted = new MemoryStream())
				{
					dest.Position = 0;
					Program.Decrypt(dest, decrypted, key, iv);

					decrypted.Position = 0;
					using (var reader = new StreamReader(decrypted))
					{
						var actualSecret = reader.ReadToEnd();
						Console.WriteLine("Decrypted secret: {0}", actualSecret);

						actualSecret.Should().Be(secret);
					}
				}
			}
		}

		[Test]
		public void TestEncryptDecrypt2()
		{
			const string password = "The flash is faster than usain bolt";
			const int iterations = 761;
			var salt = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
			byte[] key;
			byte[] iv;
			Program.GenerateKeyAndInitializationVector(password, salt, iterations, 256, 128, out key, out iv);

			var secret = "This is a secret: Clark Cent is the batman!";
			File.WriteAllText("cleartext", secret);

			if (File.Exists("encrypted"))
				File.Delete("encrypted");
			Program.Encrypt("cleartext", "encrypted", key, iv);

			if (File.Exists("actualCleartext"))
				File.Delete("actualCleartext");
			Program.Decrypt("encrypted", "actualCleartext", key, iv);

			var actualSecret = File.ReadAllText("actualCleartext");
			actualSecret.Should().Be(secret);
		}
	}
}