with Safe_Elf_Parser; use Safe_Elf_Parser;
with Interfaces; use Interfaces;
with Interfaces.C; use Interfaces.C;

procedure Safe_Elf_Parser_Tests.Check_Bit_Conversions with SPARK_Mode => On is
	-- We will check Get16, Get32, Get64.
	subtype ByteArray16 is ByteArray (0 .. 1);
	subtype ByteArray32 is ByteArray (0 .. 3);
	subtype ByteArray64 is ByteArray (0 .. 7);

	bArray16LE : constant ByteArray16 := (16#0_00#, 16#0_88#); -- 34816
	bArray32LE : constant ByteArray32 := (16#0_EF#, 16#BE#, 16#AD#, 16#DE#); -- (0xDEADBEEF)
	bArray64LE : constant ByteArray64 := (16#BE#, 16#BA#, 16#FE#, 16#CA#, 16#EF#, 16#BE#, 16#AD#, 16#DE#); -- (0xDEADBEEFCAFEBABE) 

	bArray16BE : constant ByteArray16 := (16#0_88#, 16#0_00#); -- 34816
	bArray32BE : constant ByteArray32 := (16#0_DE#, 16#AD#, 16#BE#, 16#EF#);
	bArray64BE : constant ByteArray64 := (16#DE#, 16#AD#, 16#BE#, 16#EF#, 16#CA#, 16#FE#, 16#BA#, 16#BE#);

begin
	-- Verify Get16
	pragma Assert(
		Get16(bArray16LE, 0, True) = Get16(bArray16BE, 0, False) and then
		Get16(bArray16LE, 0, True) = 34816
	);

	-- Verify Get32
	pragma Assert(
		Get32(bArray32LE, 0, True) = Get32(bArray32BE, 0, False) and then
		Get32(bArray32LE, 0, True) = 16#DEADBEEF#
	);

	-- Verify Get64
	pragma Assert(
		Get64(bArray64LE, 0, True) = Get64(bArray64BE, 0, False) and then
		Get64(bArray64LE, 0, True) = 16#DEADBEEFCAFEBABE#
	);
end;
