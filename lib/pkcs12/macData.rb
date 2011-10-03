require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/digestInfo'
require 'pkcs12/random'
require 'openssl'


module PKCS12
  class MacData
    attr_reader :mac, :macSalt, :iterations

    def initialize(mac, macSalt, iterations)
      @mac = mac
      @macSalt = macSalt
      @iterations = iterations
    end

    def verify(password, content)
      mackey = derive_mackey(password)
      calc = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, mackey, content)
      if calc != @mac.digest
        raise "MAC verification failed"
      end
    end

    def derive_mackey(password)
      Random.derive_mackey(password, @macSalt, @iterations, 20)
    end

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # mac
      ctx.scandump("mac:")
      mac = DigestInfo.load(loadport, ctx.child(2))
      # macSalt
      obj = loadport.read(:OCTET_STRING)
      macSalt = obj.value
      ctx.scandump("macSalt: #{obj.taginfo} #{obj.hexencode}")
      # iterations
      if loadport.eof?
        iterations = 1
      else
        obj = loadport.read(:INTEGER)
        iterations = obj.value
        ctx.scandump("iterations: #{obj.taginfo} #{iterations}")
      end
      new(mac, macSalt, iterations)
    end
  end
end
