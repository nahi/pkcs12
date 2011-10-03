require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/digestAlgorithmIdentifier'


module PKCS12
  class DigestInfo
    attr_reader :digestAlgorithm, :digest

    def initialize(digestAlgorithm, digest)
      @digestAlgorithm = digestAlgorithm
      @digest = digest
    end

    def self.load(loadport, ctx = LoadContext.new)
      # SEQUENCE of ...
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # digestAlgorithm
      ctx.scandump("digestAlgorithm:")
      digestAlgorithm = DigestAlgorithmIdentifier.load(loadport, ctx.child(2))
      # digest
      obj = loadport.read(:OCTET_STRING)
      digest = obj.value
      ctx.scandump("digest: #{obj.taginfo} #{obj.hexencode}")
      new(digestAlgorithm, digest)
    end
  end
end
