require 'pkcs12/asn1/object'


module PKCS12
  module ASN1
    class BitString < Object
      def dump
        "\0" + @value
      end

      def self.load(value)
        unused = value[0, 1].unpack("C")[0]
        new(value[1..-1])
      end
    end
  end
end
