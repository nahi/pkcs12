require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/contentType'
require 'pkcs12/algorithmIdentifier'


module PKCS12
  class EncryptedContentInfo
    attr_reader :contentType, :contentEncryptionAlgorithm, :encryptedContent, :safeContent

    def initialize(contentType, contentEncryptionAlgorithm, encryptedContent)
      @contentType = contentType
      @contentEncryptionAlgorithm = contentEncryptionAlgorithm
      @encryptedContent = encryptedContent
    end

    def safeContents
      @safeContent.safeContents
    end

    def decrypt(password, ctx = LoadContext.new)
      value = @contentEncryptionAlgorithm.decrypt(password, @encryptedContent)
      loadport = ASN1::Port.for(value)
      ctx.scandump("[DECRYPTED] safeContent:")
      @safeContent = SafeContents.load(loadport, ctx.child(2))
    end

    def self.load(loadport, ctx = LoadContext.new)
      # SEQUENCE of ...
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # contentType
      contentType = ContentType.load(loadport, ctx)
      # contentEncryptionAlgorithm
      ctx.scandump("contentEncryptionAlgorithm:")
      contentEncryptionAlgorithm = AlgorithmIdentifier.load(loadport, ctx.child(2))
      # encryptedContent
      unless loadport.eof?
        obj = loadport.read(:UNKNOWN)
        encryptedContent = obj.value
        ctx.scandump("encryptedContent: #{obj.taginfo}")
      end
      raise unless loadport.eof?
      obj = new(contentType, contentEncryptionAlgorithm, encryptedContent)
      if ctx.password
        obj.decrypt(ctx.password, ctx.child(2))
      end
      obj
    end
  end
end

