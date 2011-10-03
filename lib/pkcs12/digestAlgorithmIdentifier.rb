require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'


module PKCS12
  class DigestAlgorithmIdentifier
    RSA_DIGEST_OBJID = [1, 2, 840, 113549, 2]

    OBJECT = {
      :md2 => RSA_DIGEST_OBJID + [2],
      :md5 => RSA_DIGEST_OBJID + [5],
      :'id-sha1' => [1, 3, 14, 3, 2, 26],
    }

    OBJECT_ID_MAP = OBJECT.inject({}) { |r, pair| k, v = pair; r[v] = k; r }
    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      obj = loadport.read(:OBJECT_IDENTIFIER)
      objid = obj.value
      objtype = OBJECT_ID_MAP[objid] || :UNKNOWN_DIGEST_ALGORITHM_IDENTIFIER
      ctx.scandump("algorithm: #{obj.taginfo} #{objtype}")
      unless loadport.eof?
        obj = loadport.read(:NULL)
        ctx.scandump(obj.taginfo.to_s)
      end
      objtype
    end
  end
end

