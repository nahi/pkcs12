require 'pkcs12/asn1/object'
require 'pkcs12/asn1/boolean'
require 'pkcs12/asn1/integer'
require 'pkcs12/asn1/objectIdentifier'
require 'pkcs12/asn1/bitString'


module PKCS12
  module ASN1
    TAGS = {
      :UNKNOWN =>           [0x00, PKCS12::ASN1::Object],
      :BOOLEAN =>           [0x01, PKCS12::ASN1::Boolean],
      :INTEGER =>           [0x02, PKCS12::ASN1::Integer],
      :BIT_STRING =>        [0x03, PKCS12::ASN1::BitString],
      :OCTET_STRING =>      [0x04, PKCS12::ASN1::Object],
      :NULL =>              [0x05, PKCS12::ASN1::Object],
      :OBJECT_IDENTIFIER => [0x06, PKCS12::ASN1::ObjectIdentifier],
      :ObjectDescriptor =>  [0x07, PKCS12::ASN1::Object],

      :REAL =>              [0x09, PKCS12::ASN1::Object],

      :UTF8String =>        [0x0c, PKCS12::ASN1::Object],

      :SEQUENCE =>          [0x10, PKCS12::ASN1::Object],
      :SET =>               [0x11, PKCS12::ASN1::Object],
      :NumericString =>     [0x12, PKCS12::ASN1::Object],
      :PrintableString =>   [0x13, PKCS12::ASN1::Object],
      :TelexString =>       [0x14, PKCS12::ASN1::Object],
      :VideotexString =>    [0x15, PKCS12::ASN1::Object],
      :IA5String =>         [0x16, PKCS12::ASN1::Object],
      :UTCTime =>           [0x17, PKCS12::ASN1::Object],
      :GeneralizedTime =>   [0x18, PKCS12::ASN1::Object],
      :GraphicString =>     [0x19, PKCS12::ASN1::Object],
      :VisibleString =>     [0x1a, PKCS12::ASN1::Object],
      :GeneralString =>     [0x1b, PKCS12::ASN1::Object],
      :UniversalString =>   [0x1c, PKCS12::ASN1::Object],

      :BMPString =>         [0x1e, PKCS12::ASN1::Object],
    }

    TAGID_MAP = TAGS.inject({}) { |r, pair| k, v = pair; r[v[0]] = k; r }

    class TagInfo
      attr_reader :klass, :number, :is_constructed

      class << self
        private :new

        def create(klass, tagtype, is_constructed)
          number = ASN1.tagnumber(tagtype)
          new(klass, number, is_constructed)
        end

        def create_parsed(klass, number, is_constructed)
          new(klass, number, is_constructed)
        end
      end

      def initialize(klass, number, is_constructed)
        @klass = klass
        @number = number
        @is_constructed = is_constructed
      end

      def tagtype
        if tagtype = PKCS12::ASN1::TAGID_MAP[@number]
          tagtype
        else
          raise "Unknown tag type: #{@number}"
        end
      end

      def mapped_class
        ASN1.tagtype_mapped_class(tagtype)
      end
    end

    def self.tagtype_mapped_class(tagtype)
      TAGS[tagtype][1]
    end

    def self.tagnumber(tagtype)
      TAGS[tagtype][0]
    end

    def self.der2obj(taginfo, value)
      taginfo.mapped_class.load(value)
    end

    def self.obj2der(taginfo, obj)
      taginfo.mapped_class.new(obj).dump
    end
  end
end
