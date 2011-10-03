require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/encryptedData'
require 'pkcs12/safeContents'


module PKCS12
  class AuthenticatedSafe
    attr_reader :content

    def initialize(content)
      @content = content
    end

    def safeContents
      @content.collect { |item|
        item.safeContents
      }.flatten
    end

    def self.load(loadport, ctx = LoadContent.new)
      # An AuthenticateSafe contains a sequence of ContentInfo values.
      # treat this as a SEQUENCE OF ContentInfo
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("SEQUENCE_OF: #{obj.taginfo}")

      # The content field of these ContentInfo values contains either
      # plaintext, encrypted or eveloped data.
      loadport = ASN1::Port.for(obj)
      content = []
      while !loadport.eof?
        # In the case of encrypted or enveloped data, the plaintext of the data
        # holds the BER-encoding of an instance of SafeContents.
        subctx = ctx.child(2)
        content_info = ContentInfo.load(loadport, subctx)
        dataport = ASN1::Port.for(content_info.content)
        subctx = subctx.child(2)
        case content_info.contentType
        when :data
          obj = dataport.read(:OCTET_STRING)
          subctx.scandump("#{content_info.contentType}: #{obj.taginfo}")
          contentport = ASN1::Port.for(obj)
          content << SafeContents.load(contentport, subctx.child(2))
        when :encryptedData
          subctx.scandump("#{content_info.contentType}: #{obj.taginfo}")
          content << EncryptedData.load(dataport, subctx.child(2))
        when :envelopedData
          raise NotImplementedError.new
        else
          raise "Illegal contentType: #{content_info.contentType}"
        end
      end
      new(content)
    end
  end
end
