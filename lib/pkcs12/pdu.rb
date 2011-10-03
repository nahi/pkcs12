require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'


module PKCS12
  class PDU
    def self.load(port, ctx = LoadContext.new)
      loadport = ASN1::Port.for(port)
      while !loadport.eof?
        obj = loadport.read
        if obj.taginfo.is_constructed
          ctx.scandump(obj.taginfo.to_s)
          self.load(obj, ctx.child(2))
        else
          ctx.scandump("#{obj.taginfo}: #{obj.hexencode}")
        end
      end
    end
  end
end


if __FILE__ == $0
  file = ARGV.shift or raise
  PKCS12::PDU.load(File.open(file))
end
