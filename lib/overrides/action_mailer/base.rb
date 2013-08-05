require 'actionmailer_x509'

module ActionMailer #:nodoc:
  class Base #:nodoc:
    class_attribute :x509_configuration

    alias_method :old_mail, :mail

    def mail(headers = {}, &block)
      message = old_mail(headers, &block)
      x509_smime(message) if self.x509[:sign_enable] || self.x509[:crypt_enable]
    end

    private
    # X509 SMIME signing and\or crypting
    def x509_smime(message)
      config = ActionMailerX509.get_configuration(x509_configuration)
      raise Exception.new('Configuration is nil') unless config

      @signed = config.get_signer.sign(message.body.to_s) if config.sign_enable == true #message.encoded
      @coded = config.get_crypter.encode(@signed || message.body.to_s) if config.crypt_enable == true

      p = Mail.new(@coded || @signed)
      p.header.fields.each {|field| (message.header[field.name] = field.value)}

      if @coded
        #PATCH: header field 'Content-Transfer-Encoding' is not copied by the some mystic reasons
        message.header['Content-Transfer-Encoding'] = 'base64'
        message.instance_variable_set :@body_raw, Base64.encode64(p.body.to_s)
      else
        message.body = p.body.to_s
        #message.content_type = 'multipart/signed; protocol="application/x-pkcs7-signature"; micalg=sha1; '
      end
      message
    end
  end
end
