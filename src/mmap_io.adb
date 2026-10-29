with Ada.Streams.Stream_IO; use Ada.Streams.Stream_IO;

package body Mmap_IO
	with SPARK_Mode => Off
is
	-- we use stream_io now, not gnatcoll.
	function ReadChunkFromMmap (fPath : in chars_ptr; len : size_t; off : size_t) return ByteArray 
		with SPARK_Mode => Off
	is
		fPathAda : constant String := Value(fPath);
		F : File_Type;
		S : Stream_Access;

		bArray : ByteArray (0 .. len - 1);
		cnt : Count;
	begin
		-- Get Size of file
		Open (F, In_File, fPathAda);
		cnt := Size(F);

		-- Check overflow
		if len > size_t(cnt) or else off > size_t(cnt) - len then
			raise Constraint_Error with "Overread file!";
		end if;
		
		Set_Index(F, Positive_Count(off + 1));
		S := Stream(F);
		ByteArray'Read(S, bArray);

		Close (F);
		return bArray;
	exception
		when others =>
			if Is_Open(F) then
				Close(F);
			end if;
			raise;
	end;
end Mmap_IO;

