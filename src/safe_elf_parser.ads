pragma Assertion_Policy (Check);

with Interfaces.C; use Interfaces.C;
with Interfaces.C.Strings; use Interfaces.C.Strings;

package Safe_Elf_Parser with SPARK_Mode => On is
	-- as this library is intended for internal use, we only implement ELF scanning relevant to our needs.
	-- This involves identifying sections of the ELF from its header, and the dynsyms, etc.	
	
	-- Architecture Bits
	subtype ArchitectureBits is Integer with Static_Predicate => ArchitectureBits in 32 | 64 | 0;

	-- ELF Header types. Src'd from https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
	EI_NIDENT : constant Positive := 16;
	-- 32 bit types
	subtype Elf32_Half is unsigned_short; -- 16
	subtype Elf32_Word is unsigned; -- 32
	subtype Elf32_Addr is unsigned; -- 32
	subtype Elf32_Off is unsigned; -- 32
	type E_Ident_Array is array (0 .. EI_NIDENT - 1) of unsigned_char with Convention => C;

	-- 64 bit types
	subtype Elf64_Half is unsigned_short; -- 16
	subtype Elf64_Word is unsigned; -- 32
	subtype Elf64_Addr is unsigned_long_long; -- 64
	subtype Elf64_Off is unsigned_long_long; -- 64

	type Elf32_Ehdr is record
		e_ident     : E_Ident_Array; 
		e_type      : Elf32_Half;
		e_machine   : Elf32_Half;
		e_version   : Elf32_Word;
		e_entry     : Elf32_Addr;
		e_phoff     : Elf32_Off;
		e_shoff     : Elf32_Off;
		e_flags     : Elf32_Word;
		e_ehsize    : Elf32_Half;
		e_phentsize : Elf32_Half;
		e_phnum     : Elf32_Half;
		e_shentsize : Elf32_Half;
		e_shnum     : Elf32_Half;
		e_shstrndx  : Elf32_Half;
	end record
	with Convention => C, Alignment => 4, Size => 416;

	for Elf32_Ehdr use record
		e_ident     at 0   range 0 .. 127;   -- 0 .. 15 bytes
		e_type      at 16 range 0 .. 15;    -- 16 .. 17 bytes
		e_machine   at 18 range 0 .. 15;    -- 18 .. 19 bytes
		e_version   at 20 range 0 .. 31;    -- 20 .. 23 bytes
		e_entry     at 24 range 0 .. 31;    -- 24 .. 27 bytes
		e_phoff     at 28 range 0 .. 31;    -- 28 .. 31 bytes
		e_shoff     at 32 range 0 .. 31;    -- 32 .. 35 bytes
		e_flags     at 36 range 0 .. 31;    -- 36 .. 39 bytes
		e_ehsize    at 40 range 0 .. 15;    -- 40 .. 41 bytes
		e_phentsize at 42 range 0 .. 15;    -- 42 .. 43 bytes
		e_phnum     at 44 range 0 .. 15;    -- 44 .. 45 bytes
		e_shentsize at 46 range 0 .. 15;    -- 46 .. 47 bytes
		e_shnum     at 48 range 0 .. 15;    -- 48 .. 49 bytes
		e_shstrndx  at 50 range 0 .. 15;    -- 50 .. 51 bytes
	end record;

	type Elf64_Ehdr is record
		e_ident     : E_Ident_Array; 
		e_type      : Elf64_Half;
		e_machine   : Elf64_Half;
		e_version   : Elf64_Word;
		e_entry     : Elf64_Addr;
		e_phoff     : Elf64_Off;
		e_shoff     : Elf64_Off;
		e_flags     : Elf64_Word;
		e_ehsize    : Elf64_Half;
		e_phentsize : Elf64_Half;
		e_phnum     : Elf64_Half;
		e_shentsize : Elf64_Half;
		e_shnum     : Elf64_Half;
		e_shstrndx  : Elf64_Half;
	end record
	with Convention => C, Alignment => 8, Size => 512;

	-- C-compatible layout for Elf64_Ehdr.
	-- Note: 'at' and 'range' are in bits.
	for Elf64_Ehdr use record
		e_ident     at 0   range 0 .. 127;   -- 0 .. 15 bytes
		e_type      at 16 range 0 .. 15;    -- 16 .. 17 bytes
		e_machine   at 18 range 0 .. 15;    -- 18 .. 19 bytes
		e_version   at 20 range 0 .. 31;    -- 20 .. 23 bytes
		e_entry     at 24 range 0 .. 63;    -- 24 .. 31 bytes
		e_phoff     at 32 range 0 .. 63;    -- 32 .. 39 bytes
		e_shoff     at 40 range 0 .. 63;    -- 40 .. 47 bytes
		e_flags     at 48 range 0 .. 31;    -- 48 .. 51 bytes
		e_ehsize    at 52 range 0 .. 15;    -- 52 .. 53 bytes
		e_phentsize at 54 range 0 .. 15;    -- 54 .. 55 bytes
		e_phnum     at 56 range 0 .. 15;    -- 56 .. 57 bytes
		e_shentsize at 58 range 0 .. 15;    -- 58 .. 59 bytes
		e_shnum     at 60 range 0 .. 15;    -- 60 .. 61 bytes
		e_shstrndx  at 62 range 0 .. 15;    -- 62 .. 63 bytes
	end record;

	type ByteArray is array (size_t range <>) of unsigned_char; 
	subtype Elf64_Ehdr_Bytes is ByteArray (0 .. 63);
	subtype Elf32_Ehdr_Bytes is ByteArray (0 .. 51);
	subtype Elf_Single_Byte is ByteArray (0 .. 0);


	function Get16 (B : ByteArray; I : size_t; Little : Boolean) return unsigned_short with
		Global => Null,
		SPARK_Mode => On,
		Pre => B'Last >= 1 and then I >= B'First and then I < B'Last
		;

	function Get32 (B : ByteArray; I : size_t; Little : Boolean) return unsigned with
		Global => Null,
		SPARK_Mode => On,
		Pre => B'Last >= 3 and then I >= B'First and then I < B'Last - 2
		;
	
	function Get64 (B : ByteArray; I : size_t; Little : Boolean) return unsigned_long_long with
		Global => Null,
		SPARK_Mode => On,
		Pre => B'Last >= 7 and then I >= B'First and then I < B'Last - 6
		;

	function GetBits (fPath : in chars_ptr) return ArchitectureBits with
		Global => Null,
		SPARK_Mode => On,
		Export, Convention => C, External_Name => "GetBits";
	
	function GetELFHeader32 (fPath : in chars_ptr) return Elf32_Ehdr with 
		Global => Null,
		SPARK_Mode => On,
		Export, Convention => C, External_Name => "GetELFHeader32";

	function GetELFHeader64 (fPath : in chars_ptr) return Elf64_Ehdr with
		Global => Null,
		SPARK_Mode => On,
		Export, Convention => C, External_Name => "GetELFHeader64";
	
	-- Section Headers
	-- section header offset in a file is defined by e_shoff
	-- number of headers defined by e_shnum (may be 0).
	-- first entry in section header is NULL.
	
	-- 32 bit section header
	type Elf32_Shdr is record
		sh_name : Elf32_Word := 0;
		sh_type : Elf32_Word := 0;
		sh_flags : Elf32_Word := 0;
		sh_addr : Elf32_Addr := 0;
		sh_offset : Elf32_Off := 0;
		sh_size : Elf32_Word := 0;
		sh_link : Elf32_Word := 0;
		sh_info : Elf32_Word := 0;
		sh_addralign : Elf32_Word := 0;
		sh_entsize : Elf32_Word := 0;
	end record
	with Convention => C, Alignment => 4, Size => 320;

	for Elf32_Shdr use record
		sh_name at 0 range 0 .. 31; -- 0 .. 3 bytes
		sh_type at 4 range 0 .. 31; -- 4 .. 7 bytes
		sh_flags at 8 range 0 .. 31;
		sh_addr at 12 range 0 .. 31;
		sh_offset at 16 range 0 .. 31;
		sh_size at 20 range 0 .. 31;
		sh_link at 24 range 0 .. 31;
		sh_info at 28 range 0 .. 31;
		sh_addralign at 32 range 0 .. 31;
		sh_entsize at 36 range 0 .. 31;
	end record;

	-- 64 bit section header
	subtype Elf64_Xword is unsigned_long_long;
	type Elf64_Shdr is record
		sh_name : Elf64_Word := 0;
		sh_type : Elf64_Word := 0;
		sh_flags : Elf64_Xword := 0;
		sh_addr : Elf64_Addr := 0;
		sh_offset : Elf64_Off := 0;
		sh_size : Elf64_Xword := 0;
		sh_link : Elf64_Word := 0;
		sh_info : Elf64_Word := 0;
		sh_addralign : Elf64_Xword := 0;
		sh_entsize : Elf64_Xword := 0;
	end record
	with Convention => C, Alignment => 8, Size => 512;
	
	for Elf64_Shdr use record
		sh_name at 0 range 0 .. 31;
		sh_type at 4 range 0 .. 31;
		sh_flags at 8 range 0 .. 63;
		sh_addr at 16 range 0 .. 63;
		sh_offset at 24 range 0 .. 63;
		sh_size at 32 range 0 .. 63;
		sh_link at 40 range 0 .. 31;
		sh_info at 44 range 0 .. 31;
		sh_addralign at 48 range 0 .. 63;
		sh_entsize at 56 range 0 .. 63;
	end record;

	-- NOTE: C calling function will need to determine the page of Shdrs to pull
	SHDR_ARRAY_SIZE : constant Natural := 32 with Convention => C;
	type Elf32_Shdr_Array is array (size_t range 0 .. size_t(SHDR_ARRAY_SIZE - 1)) of Elf32_Shdr with Convention => C;
	type Elf64_Shdr_Array is array (size_t range 0 .. size_t(SHDR_ARRAY_SIZE - 1)) of Elf64_Shdr with Convention => C;

	-- C has no ability to return arrays, so wrap the array in a record has a hack
	-- this is effectively
	-- struct thingy { Elf32_Shdr arr[256]; size_t count };
	
	subtype Elf32_Shdr_Bytes is ByteArray (0 .. 39);
	subtype Elf32_Shdr_Array_Struct_Count is size_t range 0 .. Elf32_Shdr_Array'Length;
	type Elf32_Shdr_Array_Struct is record
		arr :	Elf32_Shdr_Array;
		count : Elf32_Shdr_Array_Struct_Count;
	end record with Convention => C;

	subtype Elf64_Shdr_Bytes is ByteArray (0 .. 63);
	subtype Elf64_Shdr_Array_Struct_Count is size_t range 0 .. Elf32_Shdr_Array'Length;
	type Elf64_Shdr_Array_Struct is record
		arr :	Elf64_Shdr_Array;
		count : Elf64_Shdr_Array_Struct_Count;
	end record with Convention => C;

	-- Note: Pages start at 0.
	function GetELFSectionHeaders32 (
		fPath : in chars_ptr;
		page : in size_t
	) 
	return Elf32_Shdr_Array_Struct
	with
		Global => Null,
		SPARK_Mode => On,
		Pre => page < (65536 / Elf32_Shdr_Array'Length), -- illogical to retrieve more than 65535 shdrs anyway
		Export, Convention => C, External_Name => "GetELFSectionHeaders32";

	-- Note: Pages start at 0.
	function GetELFSectionHeaders64 (
		fPath : in chars_ptr;
		page : in size_t
	) 
	return Elf64_Shdr_Array_Struct
	with
		Global => Null,
		SPARK_Mode => On,
		Pre => page < (65536 / Elf32_Shdr_Array'Length), -- illogical to retrieve more than 65535 shdrs anyway
		Export, Convention => C, External_Name => "GetELFSectionHeaders64";


end Safe_Elf_Parser;
