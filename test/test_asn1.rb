require 'test/unit'
require 'pkcs12/pfx'


module TestPKCS12


class TestASN1 < Test::Unit::TestCase
  include PKCS12::ASN1
  def test_integer_encode
    v = 5
    port = Port.for_write
    port.write(:Universal, :INTEGER, false, v)
    port = Port.for(port.string)
    assert_equal(v, port.read.value)
    v = 12907061240561234018249057128634981623587021436128346912837591273453123
    port = Port.for_write
    port.write(:Universal, :INTEGER, false, v)
    port = Port.for(port.string)
    assert_equal(v, port.read.value)
  end

  def test_oid_encode
    v = [1, 3, 14, 3, 2, 26]
    port = Port.for_write
    port.write(:Universal, :OBJECT_IDENTIFIER, false, v)
    port = Port.for(port.string)
    assert_equal(v, port.read.value)
  end

  def test_sequence_encode
    vint = 12345
    void = [1, 2, 3, 4, 5]
    port = Port.for_write
    port.write_sequence do |subport|
      subport.write(:Universal, :INTEGER, false, vint)
      subport.write(:ContextSpecific, :UNKNOWN, true) do |subsubport|
        subsubport.write_sequence do |subsubsubport|
          subsubsubport.write(:Universal, :INTEGER, false, vint)
        end
      end
      subport.write(:Universal, :OBJECT_IDENTIFIER, false, void)
    end
    port = Port.for(port.string)
    subport = Port.for(port.read(:SEQUENCE))
    assert_equal(vint, subport.read.value)
    subsubport = Port.for(subport.read.value)
    subsubsubport = Port.for(subsubport.read.value)
    assert_equal(vint, subsubsubport.read.value)
    assert_equal(void, subport.read.value)
  end
end


end
