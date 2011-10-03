require 'pkcs12/asn1/object'


module PKCS12
  module ASN1
    class ObjectIdentifier < Object
      def dump
        e1, e2, *body = @value
        [e1 * 40 + e2].pack("C") + body.pack("w*")
      end

      def self.load(value)
        header = value[0, 1].unpack("C")[0]
        e1 = header / 40
        e2 = header % 40
        body = value[1..-1].unpack("w*")
        new([e1, e2, *body])
      end
    end
  end
end
