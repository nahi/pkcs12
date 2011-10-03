require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'


module PKCS12
  class CertTypeIdentifier
    PKCS_OBJID = [1, 2, 840, 113549, 1]
    PKCS9_OBJID = PKCS_OBJID + [9]
    CERTTYPES_OBJID = PKCS9_OBJID + [22]

    OBJECT = {
      :x509Certificate => CERTTYPES_OBJID + [1],
      :sdsiCertificate => CERTTYPES_OBJID + [2],
    }

    OBJECT_ID_MAP = OBJECT.inject({}) { |r, pair| k, v = pair; r[v] = k; r }

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:OBJECT_IDENTIFIER)
      objid = obj.value
      objtype = OBJECT_ID_MAP[objid] || :UNKNOWN_CERT_TYPE_IDENTIFIER
      ctx.scandump("certId: #{obj.taginfo} #{objtype}")
      objtype
    end
  end
end

