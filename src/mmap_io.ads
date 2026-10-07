with Interfaces.C; use Interfaces.C;
with Interfaces.C.Strings; use Interfaces.C.Strings;

package Mmap_IO
	with SPARK_Mode => On
is 
	type ByteArray is array (size_t range <>) of unsigned_char; 
	function ReadChunkFromMmap (fPath : in chars_ptr; len : size_t; off : size_t) return ByteArray
		with SPARK_Mode => On,
		Global => Null,
		Pre => len > 0,
		Post => ReadChunkFromMmap'Result'First = 0
		and then ReadChunkFromMmap'Result'Last = len - 1; 
end Mmap_IO;
