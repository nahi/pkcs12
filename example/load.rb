require 'pkcs12/pfx'

file = ARGV.shift or raise "#{$0} file"

print 'Enter PKCS#12 Password: '
password = STDIN.gets.chomp

ctx = PKCS12::LoadContext.new(password)
pfx = PKCS12::PFX.load(File.read(file), ctx)
puts
puts "File: #{file}"
puts
puts "Certificate(s):"
pfx.find_certificates.each do |certificate|
  puts certificate.to_text
end
puts
puts "Private Key:"
p pfx.find_privatekey
