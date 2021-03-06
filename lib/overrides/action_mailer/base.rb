require 'actionmailer_x509'

module ActionMailer #:nodoc:
  class Base #:nodoc:
    class_attribute :x509_configuration

    class << self
      def x509_configuration(name = nil)
        @x509_configuration = name if name
        @x509_configuration
      end
    end

    alias_method :old_mail, :mail

    def configuration
      ActionMailerX509.get_configuration(self.class.x509_configuration)
    end

    def mail(headers = {}, &block)
      message = old_mail(headers, &block)
      x509_smime(message) if configuration.sign_require? || configuration.crypt_require?
    end

    private
    # X509 SMIME signing and\or crypting
    def x509_smime(message)
      config = ActionMailerX509.get_configuration(x509_configuration)
      raise Exception.new('Configuration is nil') unless config

      @signed = config.get_signer.sign(message.encoded) if configuration.sign_require? #message.encoded
      @coded = config.get_crypter.encode(@signed || message.encoded) if configuration.crypt_require?

      p = Mail.new(@coded || @signed)
      p.header.fields.each {|field| (message.header[field.name] = field.value)}

      if @coded
        #PATCH: header field 'Content-Transfer-Encoding' is not copied by the some mystic reasons
        message.header['Content-Transfer-Encoding'] = 'base64'
        message.instance_variable_set :@body_raw, Base64.encode64(p.body.to_s)
      else
        message.instance_variable_set :@body_raw, p.body.to_s.gsub(/(?:\A|\n)--#{p.body.boundary}(?=(?:--)?\s*$)/,"\r\n--#{p.body.boundary}")
        message.body.split! p.body.boundary
      end
      message
    end
  end
end
