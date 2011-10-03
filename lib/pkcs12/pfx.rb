require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/contentInfo'
require 'pkcs12/authenticatedSafe'
require 'pkcs12/macData'


module PKCS12
  class PFX
    attr_reader :version, :authSafe, :macData, :content

    def initialize(version, authSafe, macData, content)
      @version = version
      @authSafe = authSafe
      @macData = macData
      @content = content
    end

    def verify(password)
      @macData.verify(password, @content)
    end

    def find_certificates
      safeContents.find_all { |content|
        content.class == OpenSSL::X509::Certificate
      }
    end

    def find_privatekey
      key = safeContents.find_all { |content|
        content.class == PKCS12::PrivateKeyInfo
      }
      raise unless key.size == 1
      key[0]
    end

    def safeContents
      @authSafe.safeContents
    end

    def self.load(port, ctx = LoadContext.new)
      loadport = ASN1::Port.for(port)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)

      # SEQUENCE content
      # version
      obj = loadport.read(:INTEGER)
      version = obj.value
      ctx.scandump("version: #{obj.taginfo}: #{version}")
      # authSafe
      ctx.scandump("authSafe: ")
      content_info = ContentInfo.load(loadport, ctx.child(2))

      # contentType:
      #   signedData for public-key integrity mode
      #   data for password integrity mode
      # content:
      #   content field of the authSafe shall, either directly (data case) or
      #   indirectly (signedData case) contain a BER-encoded value of type
      #   AuthenticatedSafe.
      contentport = ASN1::Port.for(content_info.content)
      obj = contentport.read(:OCTET_STRING)
      raise unless contentport.eof?
      content = obj.value
      subctx = ctx.child(4)
      subctx.scandump(obj.taginfo.to_s)
      authport = ASN1::Port.for(obj)
      authSafe = AuthenticatedSafe.load(authport, subctx.child(2))
      # macData
      unless loadport.eof?
        ctx.scandump("macData:")
        macData = MacData.load(loadport, ctx.child(2))
        raise unless loadport.eof?
        pdu = new(version, authSafe, macData, content)
        if ctx.password
          ctx = ctx.child(2)
          pdu.verify(ctx.password)
          ctx.scandump("MAC verification OK")
        end
      end
      pdu
    end
  end
end


if __FILE__ == $0
  file = ARGV.shift or raise
  require 'pp'
  password = ARGV.shift
  ctx = PKCS12::LoadContext.new(password)
  PKCS12::PFX.load(File.open(file), ctx)
end
