require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/privateKey'


module PKCS12
  class PrivateKeyInfo
    attr_reader :version, :privateKeyAlgorithmIdentifier, :privateKey, :attributes

    def initialize(version, privateKeyAlgorithmIdentifier, privateKey, attributes)
      @version = version
      @privateKeyAlgorithmIdentifier = privateKeyAlgorithmIdentifier
      @privateKey = privateKey
      @attributes = attributes
    end

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # version
      obj = loadport.read(:INTEGER)
      version = obj.value
      ctx.scandump("version: #{obj.taginfo} #{version}")
      # privateKeyAlgorithm
      ctx.scandump("privateKeyAlgorithm:")
      privateKeyAlgorithm = AlgorithmIdentifier.load(loadport, ctx.child(2))
      # privateKey
      obj = loadport.read(:OCTET_STRING)
      dataport = ASN1::Port.for(obj)
      ctx.scandump("privateKey:")
      privateKey = PrivateKey.load(dataport, ctx.child(2))
      # attributes
      unless loadport.eof?
        obj = loadport.read
        attributes = obj.value
        ctx.scandump("attributes: #{obj.taginfo}")
      end
      new(version, privateKeyAlgorithm, privateKey, attributes)
    end
  end
end
