using System.IO;
using System.Security.Cryptography;

namespace Crypt
{
	/// <summary>
	///     This class needs to exist because crypto stream has been written with a mantra of "fuck the user".
	/// </summary>
	internal sealed class NotClosingCryptoStream : CryptoStream
	{
		public NotClosingCryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
			: base(stream, transform, mode)
		{
		}

		protected override void Dispose(bool disposing)
		{
			if (!HasFlushedFinalBlock)
				FlushFinalBlock();

			base.Dispose(false);
		}
	}
}