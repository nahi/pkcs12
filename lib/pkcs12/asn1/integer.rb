require 'pkcs12/asn1/object'


module PKCS12
  module ASN1
    class Integer < Object
      def dump
        v = @value
        buf = []
        while v > 0
          buf << (v & 0xff)
          v >>= 8
        end
        buf.reverse.pack("c*")
      end

      def self.load(value)
        num = 0
        value.each_byte do |b|
          num = (num << 8) | b
        end
        new(num)
      end
    end
  end
end
