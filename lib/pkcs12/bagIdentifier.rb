require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'


module PKCS12
  class BagIdentifier
    PKCS_OBJID = [1, 2, 840, 113549, 1]
    PKCS12_OBJID = PKCS_OBJID + [12]
    BAG_OBJID = PKCS12_OBJID + [10, 1]

    OBJECT = {
      :keyBag => BAG_OBJID + [1],
      :pkcs8ShroudedKeyBag => BAG_OBJID + [2],
      :certBag => BAG_OBJID + [3],
      :crlBag => BAG_OBJID + [4],
      :secretBag => BAG_OBJID + [5],
      :safeContentsBag => BAG_OBJID + [6],
    }

    OBJECT_ID_MAP = OBJECT.inject({}) { |r, pair| k, v = pair; r[v] = k; r }

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:OBJECT_IDENTIFIER)
      objid = obj.value
      objtype = OBJECT_ID_MAP[objid] || :UNKNOWN_BAG_IDENTIFIER
      ctx.scandump("#{objtype}: #{obj.taginfo}")
      objtype
    end
  end
end

