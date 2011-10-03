require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'


module PKCS12
  class ContentType
    PKCS_OBJID = [1, 2, 840, 113549, 1]
    PKCS7_OBJID = PKCS_OBJID + [7]

    OBJECT = {
      :data => PKCS7_OBJID + [1],
      :signedData => PKCS7_OBJID + [2],
      :envelopedData => PKCS7_OBJID + [3],
      :signedAndEnvelopedData => PKCS7_OBJID + [4],
      :digestedData => PKCS7_OBJID + [5],
      :encryptedData => PKCS7_OBJID + [6],
    }

    OBJECT_ID_MAP = OBJECT.inject({}) { |r, pair| k, v = pair; r[v] = k; r }

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:OBJECT_IDENTIFIER)
      objid = obj.value
      objtype = OBJECT_ID_MAP[objid] || :UNKNOWN_CONTENT_TYPE
      ctx.scandump("contentType: #{obj.taginfo} pkcs7-#{objtype}")
      objtype
    end
  end
end
