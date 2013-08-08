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

      @coded = config.get_crypter.encode(message.content) if configuration.crypt_require?
      @signed = config.get_signer.sign(@coded || message.content) if configuration.sign_require?

      p = Mail.new(@signed || @coded)
      p.header.fields.each {|field| (message.header[field.name] = field.value)}

      if @signed
        message.instance_variable_set :@body_raw, p.body.to_s
      else
        #PATCH: header field 'Content-Transfer-Encoding' is not copied by the some mystic reasons
        message.header['Content-Transfer-Encoding'] = 'base64'
        message.instance_variable_set :@body_raw, Base64.encode64(p.body.to_s)
      end
      message
    end
  end
end
