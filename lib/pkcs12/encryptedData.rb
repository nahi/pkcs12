require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/encryptedContentInfo'


module PKCS12
  class EncryptedData
    attr_reader :version, :encryptedContentInfo

    def initialize(version, encryptedContentInfo)
      @version = version
      @encryptedContentInfo = encryptedContentInfo
    end

    def safeContents
      @encryptedContentInfo.safeContents
    end

    def self.load(loadport, ctx = LoadContext.new)
      # SEQUENCE of ...
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # version
      obj = loadport.read(:INTEGER)
      version = obj.value
      ctx.scandump("version: #{obj.taginfo} #{version}")
      # encryptedContentInfo
      ctx.scandump("encryptedContentInfo:")
      ctx = ctx.child(2)
      encryptedContentInfo = EncryptedContentInfo.load(loadport, ctx)
      raise unless loadport.eof?
      new(version, encryptedContentInfo)
    end
  end
end
