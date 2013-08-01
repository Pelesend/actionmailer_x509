require 'actionmailer_x509'
class Notifier < ActionMailer::Base #:nodoc:
  self.prepend_view_path("#{File.dirname(__FILE__)}/../views/")

  self.x509 = {
      sign_cert: "#{File.dirname(__FILE__)}/../../certs/cert.crt",
      sign_key: "#{File.dirname(__FILE__)}/../../certs/cert.key",
      sign_passphrase: 'demo',
      crypt_cert: "#{File.dirname(__FILE__)}/../../certs/cert.crt",
      crypt_key: "#{File.dirname(__FILE__)}/../../certs/cert.key",
      crypt_passphrase: 'demo',
      crypt_cipher: 'des'
  }

  def fufu(email, from, subject = 'Empty subject')
    fufu_signed_and_or_crypted(email, from, subject)
  end

  def fufu_signed(email, from, subject = 'Empty subject for signed')
    fufu_signed_and_or_crypted(email, from, subject,  {signed: true, crypted: false })
  end

  def fufu_crypted(email, from, subject = 'Empty subject for encrypted')
    fufu_signed_and_or_crypted(email, from, subject, {signed: false, crypted: true })
  end

  def fufu_signed_and_crypted(email, from, subject = 'Empty subject for signed and encrypted')
    fufu_signed_and_or_crypted(email, from, subject, { signed: true, crypted: true })
  end

  def fufu_signed_and_or_crypted(email, from, subject = 'Empty subject', options = {})
    self.x509[:crypt_enable] = options[:crypted]
    self.x509[:sign_enable] = options[:signed]

    mail(subject: subject, to: email, from: from) do |format|
      format.text { render 'fufu' }
    end
  end
end
