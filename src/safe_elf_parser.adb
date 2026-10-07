with Ada.Unchecked_Conversion;
with Interfaces; use Interfaces;
with mmap_io; use mmap_io;

package body Safe_Elf_Parser 
	with SPARK_Mode => On
is

	function Get16 (B : ByteArray; I : size_t; Little : Boolean) return unsigned_short with
		SPARK_Mode => On

	is
	begin
		if Little then 
			return unsigned_short(Unsigned_16(B(I)) or Shift_Left(Unsigned_16(B(I+1)), 8));
		else 
			return unsigned_short(Shift_Left(Unsigned_16(B(I)), 8) or Unsigned_16(B(I+1)));
		end if;
	end;

	function Get32 (B : ByteArray; I : size_t; Little : Boolean) return unsigned with
		SPARK_Mode => On
	is
	begin
		if Little then
			return unsigned(Unsigned_32(Get16(B, I, True)) or Shift_Left(Unsigned_32(Get16(B, I+2, True)), 16));
		else
			return unsigned(Shift_Left(Unsigned_32(Get16(B,I,False)), 16) or Unsigned_32(Get16(B, I+2, False)));
		end if;
	end;

	function Get64 (B : ByteArray; I : size_t; Little : Boolean) return unsigned_long_long with
		SPARK_Mode => On
	is
	begin
		if Little then 
			return unsigned_long_long(Unsigned_64(Get32(B, I, True)) or Shift_Left(Unsigned_64(Get32(B, I+4, True)), 32));
		else
			return unsigned_long_long(Shift_Left(Unsigned_64(Get32(B, I, False)), 32) or Unsigned_64(Get32(B, I+4, False)));
		end if;
	end;
	
	function GetBits (fPath : in chars_ptr) return ArchitectureBits
		with SPARK_Mode => On 
	is
		bArray : constant Elf_Single_Byte := Elf_Single_Byte(ReadChunkFromMmap(fPath, 1, 4));
		function ElfSingleByteToUnsignedChar is
			new Ada.Unchecked_Conversion(Source => Elf_Single_Byte, Target => unsigned_char);
		bitflag : constant unsigned_char := ElfSingleByteToUnsignedChar(bArray);
	begin
		if bitflag = 1 then -- 4th byte is 01
			return 32;
		elsif bitflag = 2 then -- 4th byte is 02
			return 64;
		else -- invalid
			return 0;
		end if;
	end;

	function GetELFHeader32 (fPath : in chars_ptr) return Elf32_Ehdr
		with SPARK_Mode => On 
	is
		bArray : constant Elf32_Ehdr_Bytes := Elf32_Ehdr_Bytes(ReadChunkFromMmap(fPath, 52, 0));
		Little : constant Boolean := bArray(5) = 1;
		elfHeader32 : Elf32_Ehdr;
	begin
		   elfHeader32.e_ident     := [for I in E_Ident_Array'Range => bArray (size_t(I))];
		   elfHeader32.e_type      := Get16 (bArray, 16, Little);
		   elfHeader32.e_machine   := Get16 (bArray, 18, Little);
		   elfHeader32.e_version   := Get32 (bArray, 20, Little);
		   elfHeader32.e_entry     := (Get32 (bArray, 24, Little));
		   elfHeader32.e_phoff     := (Get32 (bArray, 28, Little));
		   elfHeader32.e_shoff     := (Get32 (bArray, 32, Little));
		   elfHeader32.e_flags     := Get32 (bArray, 36, Little);
		   elfHeader32.e_ehsize    := Get16 (bArray, 40, Little);
		   elfHeader32.e_phentsize := Get16 (bArray, 42, Little);
		   elfHeader32.e_phnum     := Get16 (bArray, 44, Little);
		   elfHeader32.e_shentsize := Get16 (bArray, 46, Little);
		   elfHeader32.e_shnum     := Get16 (bArray, 48, Little);
		   elfHeader32.e_shstrndx  := Get16 (bArray, 50, Little);
		   return elfHeader32;
	end;

	function GetELFHeader64 (fPath : in chars_ptr) return Elf64_Ehdr
		with SPARK_Mode => On 
	is
		bArray : constant Elf64_Ehdr_Bytes := Elf64_Ehdr_Bytes(ReadChunkFromMmap(fPath, 64, 0));
		Little : constant Boolean := bArray(5) = 1;
		elfHeader64 : Elf64_Ehdr;

	begin
		   elfHeader64.e_ident     := [for I in E_Ident_Array'Range => bArray (size_t(I))];
		   elfHeader64.e_type      := Get16 (bArray, 16, Little);
		   elfHeader64.e_machine   := Get16 (bArray, 18, Little);
		   elfHeader64.e_version   := Get32 (bArray, 20, Little);
		   elfHeader64.e_entry     := Get64 (bArray, 24, Little);
		   elfHeader64.e_phoff     := Get64 (bArray, 32, Little);
		   elfHeader64.e_shoff     := Get64 (bArray, 40, Little);
		   elfHeader64.e_flags     := Get32 (bArray, 48, Little);
		   elfHeader64.e_ehsize    := Get16 (bArray, 52, Little);
		   elfHeader64.e_phentsize := Get16 (bArray, 54, Little);
		   elfHeader64.e_phnum     := Get16 (bArray, 56, Little);
		   elfHeader64.e_shentsize := Get16 (bArray, 58, Little);
		   elfHeader64.e_shnum     := Get16 (bArray, 60, Little);
		   elfHeader64.e_shstrndx  := Get16 (bArray, 62, Little);
		   return elfHeader64;
	end;

	function GetELFSectionHeaders32 (fPath : in chars_ptr) return Elf32_Shdr_Array_Struct
		with SPARK_Mode => On
	is
		-- Get ELF headers (32bit).
		Little : constant Boolean := ReadChunkFromMmap(fPath, 1, 5)(0) = 1;
		elf_header_32 : constant Elf32_Ehdr := GetElfHeader32(fPath);
		
		-- From the elf_header, we can now determine the count of sections + size
		-- NOTE: EI_CLASS defines the SHDR format, but e_shentsize MAY differ.
	
		-- we will return e32sas
		e32sas : Elf32_Shdr_Array_Struct; -- 0 .. 255
	begin
		--  -- On 32 bit, ehdr should be 40 bytes.
		--  if elf_header_32.e_shentsize /= 40 then
		--  	-- invalid section header size. this is a known anti-analysis trick, 
		--  	-- so the user should repair this first.
		--  	e32sas.count := 0;
		--  	return e32sas;
		--  end if;
		--
		--  -- Otherwise, go to the offset specified by EHDR and copy 40 * num sections bytes.
		--  declare
		--  	e32sa : Elf32_Shdr_Array;
		--  	e32s : Elf32_Shdr;
		--  	bArray : Elf32_Shdr_Bytes;
		--  begin
		--  	-- BAD LOGIC
		--  	for I in 0 .. elf_header_32.e_shnum - 1 loop
		--  		bArray := Elf32_Shdr_Bytes(ReadChunkFromMmap(fPath, 40, size_t(elf_header_32.e_shoff)));
		--  		-- Rebuild each elf32_shdr and add it to the e32sas
		--  		e32s.sh_name := Get32 (bArray, 0, Little);
		--  		e32s.sh_type := Get32 (bArray, 4, Little);
		--  		e32s.sh_flags := Get32 (bArray, 8, Little);
		--  		e32s.sh_addr := Get32 (bArray, 12, Little);
		--  		e32s.sh_offset := Get32 (bArray, 16, Little);
		--  		e32s.sh_size := Get32 (bArray, 20, Little);
		--  		e32s.sh_link := Get32 (bArray, 24, Little);
		--  		e32s.sh_info := Get32 (bArray, 28, Little);
		--  		e32s.sh_addralign := Get32 (bArray, 32, Little);
		--  		e32s.sh_entsize := Get32 (bArray, 36, Little);
		--
		--  		e32sa(unsigned(I)) := e32s;
		--  		e32sas.count := e32sas.count + 1;
		--  	end loop;
		--  	e32sas.arr := e32sa;
		--  end;
		--
		--  pragma Assert( e32sas.arr'Length = elf_header_32.e_shnum );
		return e32sas;
		
	end;

end Safe_Elf_Parser;
