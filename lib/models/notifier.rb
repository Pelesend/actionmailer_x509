require 'actionmailer_x509'
class Notifier < ActionMailer::Base #:nodoc:
  self.prepend_view_path("#{File.dirname(__FILE__)}/../views/")

  self.x509 = {
    sign_cert: "lib/certs/server.crt",
    sign_key: "lib/certs/server.key",        
    sign_passphrase: "demo",
    crypt_cert: "lib/certs/ca.crt",
    crypt_cipher: 'des'
  }

  def fufu(email, from, subject = "Empty subject")
    fufu_signed_and_or_crypted(email, from, subject)
  end

  def fufu_signed(email, from, subject = "Empty subject for signed")
    fufu_signed_and_or_crypted(email, from, subject, { signed: true }, self.x509[:sign_cert], self.x509[:sign_key])
  end

  def fufu_crypted(email, from, subject = "Empty subject for encrypted")
    fufu_signed_and_or_crypted(email, from, subject, crypted: true)
  end

  def fufu_signed_and_crypted(email, from, subject = "Empty subject for signed and encrypted")

    fufu_signed_and_or_crypted(email, from, subject, { signed: true, crypted: true })
  end

  def fufu_signed_and_or_crypted(email, from, subject = "Empty subject", options = {})
  
    mail(subject: subject, to: email, from: from) do |format|
      format.text { render 'fufu' }
    end
  end
end
