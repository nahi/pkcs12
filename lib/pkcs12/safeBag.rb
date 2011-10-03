require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/bagIdentifier'
require 'pkcs12/pkcs8ShroudedKeyBag'
require 'pkcs12/certBag'
require 'pkcs12/privateKeyInfo'
require 'pkcs12/pkcs12Attribute'


module PKCS12
  class SafeBag
    attr_reader :bagId, :bagValue, :bagAttributes

    def initialize(bagId, bagValue, bagAttributes)
      @bagId = bagId
      @bagValue = bagValue
      @bagAttributes = bagAttributes
    end

    def safeContent
      case @bagId
      when :keyBag
        @bagValue
      when :pkcs8ShroudedKeyBag
        @bagValue.privateKeyInfo
      when :certBag
        @bagValue.certificate
      when :keyBag, :crlBag, :secretBag
        raise "unsupported bag type: #{bagId}"
      when :safeContentsBag
        raise "nested safeContents not supported"
      else
        raise "unknown bag type: #{bagId}"
      end
    end

    def self.load(loadport, ctx = LoadContext.new)
      # SEQUENCE of ...
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # bagId
      ctx.scandump("bagId:")
      bagId = BagIdentifier.load(loadport, ctx.child(2))
      # bagValue
      obj = loadport.read(:UNKNOWN)
      ctx.scandump("bagValue: #{obj.taginfo}")
      dataport = ASN1::Port.for(obj)
      case bagId
      when :keyBag
        bagValue = PrivateKeyInfo.load(dataport, ctx.child(2))
      when :pkcs8ShroudedKeyBag
        bagValue = Pkcs8ShroudedKeyBag.load(dataport, ctx.child(2))
      when :certBag
        bagValue = CertBag.load(dataport, ctx.child(2))
      when :crlBag, :secretBag
        raise "unsupported bag type: #{bagId}"
      when :safeContentsBag
        raise "nested safeContents not supported"
      else
        raise "unknown bag type: #{bagId}"
      end
      # bagAttributes
      unless loadport.eof?
        obj = loadport.read(:SET)
        ctx.scandump("bagAttributes: #{obj.taginfo}")
        dataport = ASN1::Port.for(obj)
        bagAttributes = []
        while !dataport.eof?
          bagAttributes << Pkcs12Attribute.load(dataport, ctx.child(2))
        end
      end
      raise unless loadport.eof?
      new(bagId, bagValue, bagAttributes)
    end
  end
end
