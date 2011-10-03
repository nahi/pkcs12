require 'pkcs12/asn1/object'


module PKCS12
  module ASN1
    class Boolean < Object
      def dump
        if @value
          "\xff"
        else
          "\x0"
        end
      end

      def self.load(value)
        case value
        when "\0"
          new(false)
        else
          new(true)
        end
      end
    end
  end
end
