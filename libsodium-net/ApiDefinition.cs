using System;
using System.Runtime.InteropServices;
using Foundation;

namespace Sodium
{
	partial interface Constants
	{
		
		// extern struct randombytes_implementation randombytes_salsa20_implementation __attribute__((visibility("default")));
		[Field("randombytes_salsa20_implementation", "__Internal")]
		randombytes_implementation randombytes_salsa20_implementation { get; }

		// extern struct randombytes_implementation randombytes_sysrandom_implementation __attribute__((visibility("default")));
		[Field("randombytes_sysrandom_implementation", "__Internal")]
		randombytes_implementation randombytes_sysrandom_implementation { get; }
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct randombytes_implementation
	{
		public Func<sbyte> implementation_name;

		public Func<uint> random;

		public Action stir;

		public Func<uint, uint> uniform;

		public Action<long> buf;

		public Func<int> close;
	}
}
