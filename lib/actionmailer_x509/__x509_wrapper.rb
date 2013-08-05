module X509Wrapper
  extend ActiveSupport::Concern

  included do |base|
    base.send :class_attribute, :x509
    base.x509 = {
        sign_enable: ActionMailerX509.sign_enable,
        sign_cert: ActionMailerX509.sign_cert,
        sign_key: ActionMailerX509.sign_key,
        sign_passphrase: ActionMailerX509.sign_passphrase,
        crypt_enable: ActionMailerX509.crypt_enable,
        crypt_cert: ActionMailerX509.crypt_cert,
        crypt_key: ActionMailerX509.crypt_key,
        crypt_passphrase: ActionMailerX509.crypt_passphrase,
        crypt_cipher: ActionMailerX509.crypt_cipher
    }
  end

  def get_crypter
    ActionMailerX509::X509.new(
        x509[:crypt_cert],
        x509[:crypt_key],
        x509[:crypt_passphrase],
        x509[:crypt_cipher])
  end

  def get_signer
    ActionMailerX509::X509.new(
        x509[:sign_cert],
        x509[:sign_key],
        x509[:sign_passphrase])
  end
end