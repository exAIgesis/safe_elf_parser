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
			return unsigned_long_long(Shift_Left(Unsigned_64(Get32(B, I, False)), 32) or Unsigned_64(Get16(B, I+4, False)));
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
		Little : constant Boolean := bArray(6) = 1;
		elfHeader32 : Elf32_Ehdr;
	begin
		   elfHeader32.e_ident     := [for I in E_Ident_Array'Range => bArray (size_t(I))];
		   elfHeader32.e_type      := Get16 (bArray, 17, Little);
		   elfHeader32.e_machine   := Get16 (bArray, 19, Little);
		   elfHeader32.e_version   := Get32 (bArray, 21, Little);
		   elfHeader32.e_entry     := (Get32 (bArray, 25, Little));
		   elfHeader32.e_phoff     := (Get32 (bArray, 29, Little));
		   elfHeader32.e_shoff     := (Get32 (bArray, 33, Little));
		   elfHeader32.e_flags     := Get32 (bArray, 37, Little);
		   elfHeader32.e_ehsize    := Get16 (bArray, 41, Little);
		   elfHeader32.e_phentsize := Get16 (bArray, 43, Little);
		   elfHeader32.e_phnum     := Get16 (bArray, 45, Little);
		   elfHeader32.e_shentsize := Get16 (bArray, 47, Little);
		   elfHeader32.e_shnum     := Get16 (bArray, 49, Little);
		   elfHeader32.e_shstrndx  := Get16 (bArray, 51, Little);
		   return elfHeader32;
	end;

	function GetELFHeader64 (fPath : in chars_ptr) return Elf64_Ehdr
		with SPARK_Mode => On 
	is
		bArray : constant Elf64_Ehdr_Bytes := Elf64_Ehdr_Bytes(ReadChunkFromMmap(fPath, 64, 0));
		Little : constant Boolean := bArray(6) = 1;
		elfHeader64 : Elf64_Ehdr;

	begin
		   elfHeader64.e_ident     := [for I in E_Ident_Array'Range => bArray (size_t(I))];
		   elfHeader64.e_type      := Get16 (bArray, 17, Little);
		   elfHeader64.e_machine   := Get16 (bArray, 19, Little);
		   elfHeader64.e_version   := Get32 (bArray, 21, Little);
		   elfHeader64.e_entry     := Get64 (bArray, 25, Little);
		   elfHeader64.e_phoff     := Get64 (bArray, 29, Little);
		   elfHeader64.e_shoff     := Get64 (bArray, 33, Little);
		   elfHeader64.e_flags     := Get32 (bArray, 37, Little);
		   elfHeader64.e_ehsize    := Get16 (bArray, 41, Little);
		   elfHeader64.e_phentsize := Get16 (bArray, 43, Little);
		   elfHeader64.e_phnum     := Get16 (bArray, 45, Little);
		   elfHeader64.e_shentsize := Get16 (bArray, 47, Little);
		   elfHeader64.e_shnum     := Get16 (bArray, 49, Little);
		   elfHeader64.e_shstrndx  := Get16 (bArray, 51, Little);
		   return elfHeader64;
	end;

end Safe_Elf_Parser;
