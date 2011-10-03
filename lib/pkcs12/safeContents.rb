require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/safeBag'


module PKCS12
  class SafeContents
    attr_reader :content

    def initialize(content)
      @content = content
    end

    def safeContents
      @content.collect { |item|
        item.safeContent
      }
    end

    def self.load(loadport, ctx = LoadContext.new)
      # The SafeContents type is made up of SafeBags.
      # treat this as a SEQUENCE OF SafeBag
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("SEQUENCE_OF: #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      ctx = ctx.child(2)
      content = []
      while !loadport.eof?
        content << SafeBag.load(loadport, ctx)
      end
      new(content)
    end
  end
end
