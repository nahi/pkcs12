require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/contentType'


module PKCS12
  class ContentInfo
    attr_reader :contentType, :content

    def initialize(contentType, content)
      @contentType = contentType
      @content = content
    end

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # contentType
      contentType = ContentType.load(loadport, ctx)
      # content
      unless loadport.eof?
        obj = loadport.read(:UNKNOWN)
        content = obj.value
        ctx.scandump("content: #{obj.taginfo}")
        raise unless loadport.eof?
      end
      new(contentType, content)
    end
  end
end
