procedure Safe_Elf_Parser_Tests.Assertions_Enabled is
begin
   begin
      pragma Assert (False, "Should raise");
   exception
      when others =>
         return; -- properly raised
   end;
   raise Program_Error with "Assertion did not raise";
end Safe_Elf_Parser_Tests.Assertions_Enabled;
