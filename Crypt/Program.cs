using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;

namespace Crypt
{
	public static class Program
	{
		private const int BufferSize = 4096;

		public static void GenerateKeyAndInitializationVector(string password, byte[] salt, int iterations,
													int keyLengthInBits, int ivLengthInBits,
													out byte[] key, out byte[] iv)
		{
			using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
			{
				key = rfc2898DeriveBytes.GetBytes(keyLengthInBits/8);
				iv = rfc2898DeriveBytes.GetBytes(ivLengthInBits/8);
			}
		}

		public static void Encrypt(string source, string dest, byte[] key, byte[] iv)
		{
			using (var destStream = File.Create(dest))
			using (var sourceStream = File.OpenRead(source))
			{
				Encrypt(sourceStream, destStream, key, iv);
			}
		}

		public static void Encrypt(Stream sourceStream, Stream destStream, byte[] key, byte[] iv)
		{
			using (var crypto = new RijndaelManaged())
			using (var cryptoStream = new NotClosingCryptoStream(destStream, crypto.CreateEncryptor(key, iv), CryptoStreamMode.Write))
			{
				var buffer = new byte[BufferSize];
				while (true)
				{
					var read = sourceStream.Read(buffer, 0, buffer.Length);
					if (read <= 0)
						break;

					cryptoStream.Write(buffer, 0, read);
				}
			}
		}

		public static void Decrypt(string source, string dest, byte[] key, byte[] iv)
		{
			using (var sourceStream = File.OpenRead(source))
			using (var destStream = File.OpenWrite(dest))
			{
				Decrypt(sourceStream, destStream, key, iv);
			}
		}

		public static void Decrypt(Stream sourceStream, Stream destStream, byte[] key, byte[] iv)
		{
			using (var rijndael = new RijndaelManaged())
			using (var cryptoStream = new NotClosingCryptoStream(sourceStream, rijndael.CreateDecryptor(key, iv), CryptoStreamMode.Read))
			{
				var buffer = new byte[BufferSize];
				while (true)
				{
					var read = cryptoStream.Read(buffer, 0, buffer.Length);
					if (read <= 0)
						break;

					destStream.Write(buffer, 0, read);
				}
			}
		}

		enum Mode
		{
			Encrypt,
			Decrypt
		}

		private static bool ParseArgs(string[] args, out string source, out string dest, out Mode mode)
		{
			source = null;
			dest = null;
			mode = (Mode)(-1);

			if (args.Length < 3)
			{
				return false;
			}

			if (!Enum.TryParse(args[0], true, out mode))
			{
				Console.WriteLine("ERROR: Unknown mode: {1}");
				return false;
			}

			source = args[1];
			if (!File.Exists(source))
			{
				Console.WriteLine("ERROR: source does not exist");
				return false;
			}

			dest = args[2];
			return true;
		}

		private static void PrintUsage()
		{
			Console.WriteLine("Usage: crypt.exe encrypt|decrypt source dest");
			Console.WriteLine("\tsource must point to an existing file");
			Console.WriteLine("\tIf dest points towards an existing file, it will be overwritten");
		}

		public static int Main(string[] args)
		{
			string source, dest;
			Mode mode;
			if (!ParseArgs(args, out source, out dest, out mode))
			{
				PrintUsage();
				return -1;
			}

			const string passwordName = "CRYPT_PASSWORD";
			var password = Environment.GetEnvironmentVariable(passwordName);
			if (string.IsNullOrEmpty(password))
			{
				Console.WriteLine("Please supply a non-empty password through the {0} environment variable", "CRYPT_PASSWORD");
				return -1;
			}

			const string saltName = "CRYPT_SALT";
			const int saltLength = 8;
			var saltValue = Environment.GetEnvironmentVariable(saltName);
			if (string.IsNullOrEmpty(saltValue))
			{
				Console.WriteLine(
					"Please supply a non-empty, comma separated salt of length {0} bytes through the {1} environment variable",
					saltLength,
					saltName);
				return -1;
			}

			var bytesValue = saltValue.Split(',');
			if (bytesValue.Length != saltLength)
			{
				Console.WriteLine("Please supply a comma separated salt of length {0} bytes ({1} bytes were given)", saltName, bytesValue.Length);
				return -1;
			}

			var salt = new byte[saltLength];
			for(int i = 0; i < saltLength; ++i)
			{
				byte @byte;
				if (!byte.TryParse(bytesValue[i], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out @byte))
				{
					Console.WriteLine(
						"Please supply a comma separated salt of length {0} bytes where each byte is represented through a hexadecimal number without prefix, such as 00 or FF",
						saltLength);
					return -1;
				}

				salt[i] = @byte;
			}

			const string numIterationsName = "CRYPT_NUM_ITERATIONS";
			var numIterationsValue = Environment.GetEnvironmentVariable(numIterationsName);
			if (string.IsNullOrEmpty(numIterationsValue))
			{
				Console.WriteLine(
					"Please supply the number of iterations to use for rfc2898 as an integer between 1 and int.max through the {0} variable",
					numIterationsName);
				return -1;
			}

			int numIterations;
			if (!int.TryParse(numIterationsValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out numIterations))
			{
				Console.WriteLine(
					"Please supply the number of iterations to use for rfc2898 as an integer between 1 and int.max");
				return -1;
			}

			if (numIterations <= 0)
			{
				Console.WriteLine(
					"Please supply a number greater or equal to one as the number of iterations");
				return -1;
			}

			const int keyLength = 256;
			const int ivLength = 128;
			byte[] key;
			byte[] iv;
			GenerateKeyAndInitializationVector(password, salt, numIterations, keyLength, ivLength, out key, out iv);

			switch (mode)
			{
				case Mode.Encrypt:
					Encrypt(source, dest, key, iv);
					return 0;

				case Mode.Decrypt:
					Decrypt(source, dest, key, iv);
					return 0;

				default:
					Console.WriteLine("ERROR: Unknown mode {0}", mode);
					PrintUsage();
					return -1;
			}
		}
	}
}