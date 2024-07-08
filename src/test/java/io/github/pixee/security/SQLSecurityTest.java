package io.github.pixee.security;

import org.junit.jupiter.api.Test;

final class SQLSecurityTest {

  @Test
  void it_accepts_alphanumeric_table_names(){
    assert SQLSecurity.alphanumericValidator("the_quick_brown_fox_jumps_over_the_lazy_dog_1234567890");
  }

  @Test
  void it_accepts_schema_table_name(){
    assert SQLSecurity.alphanumericValidator("schema_name.table_name");
  }

  @Test
  void it_rejects_non_alphanumeric(){
    assert !SQLSecurity.alphanumericValidator("\"reject_this\" where 1=1");
  }

}
