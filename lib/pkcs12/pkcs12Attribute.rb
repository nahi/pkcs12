require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'


module PKCS12
  class Pkcs12Attribute
    PKCS_OBJID = [1, 2, 840, 113549, 1]
    PKCS9_OBJID = PKCS_OBJID + [9]
    MICROSOFT_PKCS12 = [1, 3, 6, 1, 4, 1, 311, 17]

    OBJECT = {
      :'pkcs-9-at-friendlyName' => PKCS9_OBJID + [20],
      :'pkcs-9-at-localKeyId' => PKCS9_OBJID + [21],

      :'szOID_PKCS_12_KEY_PROVIDER_NAME_ATTR' => MICROSOFT_PKCS12 + [1],
      :'szOID_LOCAL_MACHINE_KEYSET' => MICROSOFT_PKCS12 + [2],
    }

    OBJECT_ID_MAP = OBJECT.inject({}) { |r, pair| k, v = pair; r[v] = k; r }

    attr_reader :attrId, :attrValues

    def initialize(attrId, attrValues)
      @attrId = attrId
      @attrValues = attrValues
    end

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("SEQUENCE_OF: #{obj.taginfo}")
      ctx = ctx.child(2)
      loadport = ASN1::Port.for(obj)
      # attrId
      obj = loadport.read(:OBJECT_IDENTIFIER)
      objid = obj.value
      attrId = OBJECT_ID_MAP[objid] || :UNKNOWN_PKCS12_ATTRIBUTE
      ctx.scandump("attrId: #{obj.taginfo} #{attrId}")
      # attrValues
      obj = loadport.read(:SET)
      ctx.scandump("SET: #{obj.taginfo}")
      dataport = ASN1::Port.for(obj)
      ctx = ctx.child(2)
      attrValues = []
      while !dataport.eof?
        obj = dataport.read
        ctx.scandump("#{obj.taginfo} #{obj.hexencode}")
        attrValues << obj.value
      end
      new(attrId, attrValues)
    end
  end
end
