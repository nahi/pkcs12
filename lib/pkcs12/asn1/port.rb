require 'stringio'
require 'pkcs12/asn1/taginfo'


module PKCS12
  module ASN1
    class Port
      class << self
        private :new

        def for(port)
          if port.is_a?(PKCS12::ASN1::Object)
            port = StringIO.new(port.value)
          elsif !port.respond_to?(:read)
            port = StringIO.new(port.to_s)
          end
          new(port)
        end

        def for_write
          new(StringIO.new)
        end
      end

      attr_reader :readlength, :writelength

      def initialize(port)
        @port = port
        @readlength = 0
        @writelength = 0
        @str = ''
      end

      def string
        @port.string
      end

      def read_boolean
        read(:BOOLEAN).value
      end

      def read_null
        read(:NULL)
        nil
      end

      def read_integer
        read(:INTEGER).value
      end
      
      def read_string
        read(:PrintableString).value
      end

      def read_bitstring
        read(:BIT_STRING).value
      end

      def read_utf8string
        read(:UTF8String).value
      end

      def read_object_identifier
        read(:OBJECT_IDENTIFIER).value
      end

      def read_set(expected = nil, &block)
        obj = read(:SET)
        port = Port.for(obj)
        if block
          yield(port)
        else
          port.read_all(expected)
        end
      end

      def read_sequence
        obj = read(:SEQUENCE)
        yield(Port.for(obj))
      end

      def read_all(expected = nil)
        ary = []
        while !eof?
          ary << read(expected).value
        end
        ary
      end

      def read(expected = nil)
        taginfo = read_tag
        length = read_length
        value = read_bytes(length)
        if expected
          if taginfo.tagtype.to_s != expected.to_s
            raise "#{expected} expected but #{taginfo.tagtype} given"
          end
        end
        obj = ASN1.der2obj(taginfo, value)
        obj.taginfo = taginfo
        obj
      end

      MASK_KLASS =  0b11000000
      MASK_PC =     0b00100000
      MASK_NUMBER = 0b00011111

      def read_tag
        ch = read_1octet
        klass = parse_klass(ch & MASK_KLASS)
        number = ch & MASK_NUMBER
        is_constructed = ((ch & MASK_PC) != 0)

        if number == MASK_NUMBER
          number = 0
          while true do
            ch = read_1octet
            number = (number << 7) | (ch & 0x7f)
            break if (ch & 0x80) != 0x80
          end
        end 
        TagInfo.create_parsed(klass, number, is_constructed)
      end

      def read_length
        length = 0
        ch = read_1octet
        if (ch & 0x80) == 0
          length = ch & 0x7f
        else
          length_length = ch & 0x7f
          length_length.times do
            ch = read_1octet
            length = (length << 8) | ch
          end
        end
        length
      end

      KLASS_VALUE_MAP = {
        :Universal =>       0b00000000,
        :Application =>     0b01000000,
        :ContextSpecific => 0b10000000,
        :Private =>         0b11000000
      }

      def parse_klass(klass_value)
        KLASS_VALUE_MAP.key(klass_value) or
          raise "Unknown class encoding: #{klass_value}"
      end

      def encode_klass(klass)
        KLASS_VALUE_MAP[klass] or raise "Unknown class: #{klass}"
      end

      def read_1octet
        read_bytes(1).unpack("C")[0]
      end

      def read_bytes(size = nil)
        if size.nil?
          return @str + @port.read
        end
        if @str.empty?
          result = @port.read(size)
        elsif @str.size < size
          result = @str
          result << @port.read(size - @str.size)
          @str = ''
        else
          result = @str[0, size]
          @str = @str[size..-1]
        end
        @readlength += result.size
        if result.size != size
          raise "Input stream corruption: #{result.size}/#{size}"
        end
        result
      end

      def eof?
        @port.eof?
      end

      def write_boolean(obj)
        write(:Universal, :BOOLEAN, false, obj)
      end

      def write_null
        write(:Universal, :NULL, false, '')
      end

      def write_integer(obj)
        write(:Universal, :INTEGER, false, obj)
      end

      def write_string(obj)
        write(:Universal, :PrintableString, false, obj)
      end

      def write_bitstring(obj)
        write(:Universal, :BIT_STRING, false, obj)
      end

      def write_utf8string(obj)
        write(:Universal, :UTF8String, false, obj)
      end

      def write_object_identifier(obj)
        write(:Universal, :OBJECT_IDENTIFIER, false, obj)
      end

      def write_set(obj = nil, &block)
        write(:Universal, :SET, true, obj, &block)
      end

      def write_sequence(obj = nil, &block)
        write(:Universal, :SEQUENCE, true, obj, &block)
      end

      def write(klass, tagtype, is_constructed, obj = nil, &block)
        taginfo = TagInfo.create(klass, tagtype, is_constructed)
        der = nil
        if block
          subport = Port.for_write
          block.call(subport)
          der = subport.string
        else
          der = ASN1.obj2der(taginfo, obj)
        end
        write_tag(taginfo)
        write_length(der.size)
        write_bytes(der)
      end

      def write_tag(taginfo)
        ch = 0
        ch |= encode_klass(taginfo.klass)
        ch |= MASK_PC if taginfo.is_constructed

        number = taginfo.number
        if number < MASK_NUMBER
          ch |= number
          write_1octet(ch)
        else
          ch |= MASK_NUMBER
          write_1octet(ch)
          while number > 0
            write_1octet((number & 0x7f) | 0x80)
            number >>= 7
          end
        end
      end

      def write_length(length)
        if length < 0x80
          write_1octet(length)
        else
          buf = []
          while length > 0
            buf << length
            length >>= 8
          end
          write_1octet(buf.size | 0x80)
          write_bytes(buf.reverse.pack("C*"))
        end
      end

      def write_1octet(ch)
        write_bytes([ch].pack("C"))
      end

      def write_bytes(bytes)
        @port.write(bytes)
      end
    end
  end
end
