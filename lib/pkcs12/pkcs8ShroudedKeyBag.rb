require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/privateKeyInfo'


module PKCS12
  class Pkcs8ShroudedKeyBag
    attr_reader :algorithm, :encryptedData, :privateKeyInfo

    def initialize(algorithm, encryptedData)
      @algorithm = algorithm
      @encryptedData = encryptedData
    end

    def decrypt(password, ctx = LoadContext.new)
      value = @algorithm.decrypt(password, @encryptedData)
      loadport = ASN1::Port.for(value)
      ctx.scandump("[DECRYPTED] privateKey:")
      ctx = ctx.child(2)
      @privateKeyInfo = PrivateKeyInfo.load(loadport, ctx)
    end

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # encryptionAlgorithm
      algorithm = AlgorithmIdentifier.load(loadport, ctx)
      # encryptedData
      obj = loadport.read(:OCTET_STRING)
      ctx.scandump("encryptedData: #{obj.taginfo}")
      encryptedData = obj.value
      obj = new(algorithm, encryptedData)
      if ctx.password
        obj.decrypt(ctx.password, ctx.child(2))
      end
      obj
    end
  end
end
