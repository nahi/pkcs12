require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'


module PKCS12
  class PrivateKey
    attr_reader :version
    attr_accessor :modulus, :publicExponent, :privateExponent, :prime1, :prime2, :exponent1, :exponent2, :coefficient, :otherPrimeInfos

    def initialize(version)
      @version = version
    end

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # version
      obj = loadport.read(:INTEGER)
      version = obj.value
      ctx.scandump("version: #{obj.taginfo} #{version}")
      # modulus
      obj = loadport.read(:INTEGER)
      modulus = obj.value
      ctx.scandump("modulus: #{obj.taginfo} #{modulus}")
      # publicExponent
      obj = loadport.read(:INTEGER)
      publicExponent = obj.value
      ctx.scandump("publicExponent: #{obj.taginfo} #{publicExponent}")
      # privateExponent
      obj = loadport.read(:INTEGER)
      privateExponent = obj.value
      ctx.scandump("privateExponent: #{obj.taginfo} #{privateExponent}")
      # prime1
      obj = loadport.read(:INTEGER)
      prime1 = obj.value
      ctx.scandump("prime1: #{obj.taginfo} #{prime1}")
      # prime2
      obj = loadport.read(:INTEGER)
      prime2 = obj.value
      ctx.scandump("prime2: #{obj.taginfo} #{prime2}")
      # exponent1
      obj = loadport.read(:INTEGER)
      exponent1 = obj.value
      ctx.scandump("exponent1: #{obj.taginfo} #{exponent1}")
      # exponent2
      obj = loadport.read(:INTEGER)
      exponent2 = obj.value
      ctx.scandump("exponent2: #{obj.taginfo} #{exponent2}")
      # coefficient
      obj = loadport.read(:INTEGER)
      coefficient = obj.value
      ctx.scandump("coefficient: #{obj.taginfo} #{coefficient}")
      # otherPrimeInfos
      unless loadport.eof?
        otherPrimeInfos = []
        ctx.scandump("otherPrimeInfos:")
        ctx = ctx.child(2)
        while !loadport.eof?
          obj = loadport.read
          ctx.scandump(obj.taginfo.to_s)
          otherPrimeInfos << obj.value
        end
      end
      obj = new(version)
      obj.modulus = modulus
      obj.publicExponent = publicExponent
      obj.privateExponent = privateExponent
      obj.prime1 = prime1
      obj.prime2 = prime2
      obj.exponent1 = exponent1
      obj.exponent2 = exponent2
      obj.coefficient = coefficient
      obj.otherPrimeInfos = otherPrimeInfos
      obj
    end
  end
end
