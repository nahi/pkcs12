module PKCS12
  class LoadContext
    attr_reader :password
    attr_reader :indent

    def initialize(password = nil)
      @password = password
      @indent = 0
    end

    def child(add_indent)
      ctx = LoadContext.new
      ctx.password = @password
      ctx.indent = @indent + add_indent
      ctx
    end

    def scandump(line)
      puts format(line, @indent) if $DEBUG
    end

protected

    def password=(password)
      @password = password
    end

    def indent=(indent)
      @indent = indent
    end

  private

    def format(str, indent = nil)
      str = trim_eol(str)
      str = trim_indent(str)
      if indent
        str.gsub(/^/, " " * indent)
      else
        str
      end
    end
  end
end
