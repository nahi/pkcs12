module PKCS12
  module ASN1
    class Object
      attr_accessor :value
      attr_accessor :taginfo

      def initialize(value)
        @value = value
      end

      def hexencode
        self.class.hexencode(@value)
      end

      def dump
        @value
      end

      def self.load(value)
        new(value)
      end

      def self.hexencode(value)
        value.unpack("H*")[0].upcase
      end
    end
  end
end
