require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/random'


module PKCS12
  class AlgorithmIdentifier
    PKCS_OBJID = [1, 2, 840, 113549, 1]
    PKCS1_OBJID = PKCS_OBJID + [1]
    PKCS5_OBJID = PKCS_OBJID + [5]
    PKCS12_OBJID = PKCS_OBJID + [12]
    PBE_OBJID = PKCS12_OBJID + [1]

    OBJECT = {
      # PKCS#1
      :rsaEncryption => [PKCS1_OBJID + [1]],

      # PKCS#5
      :'pbeWithMD5AndDES-CBC' => [PKCS5_OBJID + [3], 8, 0, "des-cbc"],

      # PKCS#12
      :pbeWithSHAAnd128BitRC4 => [PBE_OBJID + [1], 16, 0, "rc4"],
      :pbeWithSHAAnd40BitRC4 => [PBE_OBJID + [2], 5, 0, "rc4-40"],
      :'pbeWithSHAAnd3-KeyTripleDES-CBC' => [PBE_OBJID + [3], 24, 8, "des-ede3-cbc"],
      :'pbeWithSHAAnd2-KeyTripleDES-CBC' => [PBE_OBJID + [4], 16, 8, "des-ede-cbc"],
      :'pbeWithSHAAnd128BitRC2-CBC' => [PBE_OBJID + [5], 16, 8, "rc2-cbc"],
      :'pbeWithSHAAnd40BitRC2-CBC' => [PBE_OBJID + [6], 5, 8, "rc2-40-cbc"],
    }

    OBJECT_ID_MAP = OBJECT.inject({}) { |r, pair| k, v = pair; r[v[0]] = k; r }

    attr_reader :algorithm, :salt, :iterations

    def initialize(algorithm, salt, iterations)
      @algorithm = algorithm
      @salt = salt
      @iterations = iterations
    end

    def decrypt(password, ciphertext)
      cipher = create_cipher
      cipher.decrypt
      key = derive_key(password)
      iv = derive_iv(password)
      cipher.key = key
      cipher.iv = iv if iv
      plaintext = cipher.update(ciphertext) + cipher.final
      plaintext
    end

    def derive_key(password)
      Random.derive_key(password, @salt, @iterations, keybytes)
    end

    def derive_iv(password)
      return nil if ivbytes == 0
      Random.derive_iv(password, @salt, @iterations, ivbytes)
    end

    def keybytes
      OBJECT[@algorithm][1]
    end

    def ivbytes
      OBJECT[@algorithm][2]
    end

    def create_cipher
      OpenSSL::Cipher::Cipher.new(OBJECT[@algorithm][3])
    end

    def self.load(loadport, ctx = LoadContext.new)
      # SEQUENCE of ...
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # algorithm
      obj = loadport.read(:OBJECT_IDENTIFIER)
      objid = obj.value
      algorithm = OBJECT_ID_MAP[objid] || :UNKNOWN_ALGORITHM_IDENTIFIER
      ctx.scandump("algorithm: #{obj.taginfo} #{algorithm}")
      # parameters
      unless loadport.eof?
        ctx.scandump("parameters:")
        obj = loadport.read
        ctx.scandump(obj.taginfo.to_s)
        if obj.taginfo.is_constructed
          dataport = ASN1::Port.for(obj)
          ctx = ctx.child(2)
          # PBKDF1 only?
          obj = dataport.read(:OCTET_STRING)
          salt = obj.value
          ctx.scandump("salt: #{obj.taginfo} #{obj.hexencode}")
          obj = dataport.read(:INTEGER)
          iterations = obj.value
          ctx.scandump("iterations: #{obj.taginfo} #{iterations}")
        end
      end
      raise unless loadport.eof?
      new(algorithm, salt, iterations)
    end
  end
end

