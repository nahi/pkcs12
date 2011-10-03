require 'digest/sha1'
require 'openssl'


module PKCS12
  class Random
    ID = {
      :key => 1,
      :iv => 2,
      :mackey => 3
    }

    def self.derive_key(password, salt, r, n)
      derive(:key, password, salt, r, n)
    end

    def self.derive_iv(password, salt, r, n)
      derive(:iv, password, salt, r, n)
    end

    def self.derive_mackey(password, salt, r, n)
      derive(:mackey, password, salt, r, n)
    end

    def self.derive(type, orgpassword, salt, r, n)
      password = to_bmppassword(orgpassword)
      id = ID[type] or raise "Unknown type: #{type}"
      # assume SHA1
      v = 64
      u = 20
      saltlen = v * nextint(salt.size, v)
      passwordlen = v * nextint(password.size, v)
      d = [id].pack("c") * v
      s = concat_to_length(salt, saltlen)
      p = concat_to_length(password, passwordlen)
      i = s + p
      c = nextint(n, u)
      k = nextint(s.length, v) + nextint(p.length, v)
      ai = Array.new(c)
      reg = Regexp.new("[\0-\xff]{#{v}}", nil, 'NONE')
      1.upto(c) do |idx|
        ai[idx - 1] = sha1times(d + i, r)
        b = concat_to_length(ai[idx - 1], v)
        bplus1 = OpenSSL::BN.new(b, 2) + 1
        i = i.scan(reg).collect { |part|
          ij = (OpenSSL::BN.new(part, 2) + bplus1).to_s(2)
          if ij.length > v
            ij = ij[1..-1]
          else
            ij += "\0" * v
            ij = ij[0, v]
          end
          ij
        }.join
      end
      a = ai.join
      a[0, n]
    end
    
    def self.to_bmppassword(password)
      (password + "\0").unpack("U*").pack("n*")
    end

    def self.nextint(num, div)
      1 + (num - 1) / div
    end

    def self.concat_to_length(basestr, length)
      (basestr * nextint(length, basestr.length))[0, length]
    end

    def self.sha1times(target, iterations)
      iterations.times do
        target = Digest::SHA1.digest(target)
      end
      target
    end
  end
end
