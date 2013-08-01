module X509Wrapper
  extend ActiveSupport::Concern

  included do |base|
    base.send :class_attribute, :x509
    base.x509 = {
        sign_enable: true,
        crypt_enable: true,
        sign_cert: "#{File.dirname(__FILE__)}/../../certs/cert.crt",
        sign_key: "#{File.dirname(__FILE__)}/../../certs/cert.key",
        sign_passphrase: 'demo',
        crypt_cert: "#{File.dirname(__FILE__)}/../../certs/cert.crt",
        crypt_key: "#{File.dirname(__FILE__)}/../../certs/cert.key",
        crypt_passphrase: 'demo',
        crypt_cipher: 'des'
    }

    #base.x509 = {
    #    sign_enable: true,
    #    sign_cert: 'certs/server.crt',
    #    sign_key: 'certs/server.key',
    #    sign_passphrase: 'hisp',
    #    crypt_enable: true,
    #    crypt_cert: 'certs/ca.crt',
    #    crypt_key: 'certs/ca.key',
    #    crypt_passphrase: 'hisp',
    #    crypt_cipher: 'des'
    #}
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