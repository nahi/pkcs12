require 'pkcs12/asn1/port'
require 'pkcs12/loadContext'
require 'pkcs12/certTypeIdentifier'
require 'openssl'


module PKCS12
  class CertBag
    attr_reader :certId, :certValue, :certificate

    def initialize(certId, certValue, certificate)
      @certId = certId
      @certValue = certValue
      @certificate = certificate
    end

    def self.load(loadport, ctx = LoadContext.new)
      obj = loadport.read(:SEQUENCE)
      ctx.scandump("+---- #{obj.taginfo}")
      loadport = ASN1::Port.for(obj)
      # certId
      certId = CertTypeIdentifier.load(loadport, ctx)
      # certValue
      obj = loadport.read(:UNKNOWN)
      certValue = obj.value
      dataport = ASN1::Port.for(obj)
      case certId
      when :x509Certificate
        obj = dataport.read(:OCTET_STRING)
        ctx.scandump("OpenSSL parsed certificate dump: #{obj.taginfo}")
        ctx = ctx.child(2)
        certificate = OpenSSL::X509::Certificate.new(obj.value)
        ctx.scandump(certificate.to_text)
      when :sdsiCertificate
        obj = dataport.read(:IA5String)
        raise "unsupported certificate type: #{certId}"
      else
        raise "unknown certificate type: #{certId}"
      end
      new(certId, certValue, certificate)
    end
  end
end
