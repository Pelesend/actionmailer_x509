class Configuration
  def initialize(params = {})
    params.symbolize_keys!
    params.each_pair { |k, v| self.send("#{k}=".to_sym, v) }
  end

  class_attribute :sign_enable
  self.sign_enable = false

  class_attribute :crypt_enable
  self.crypt_enable = false

  class_attribute :crypt_cipher
  self.crypt_cipher = 'des'

  class_attribute :certs_path
  self.certs_path = Rails.root.join('certs')

  class_attribute :sign_cert
  class_attribute :sign_key
  class_attribute :sign_passphrase
  class_attribute :crypt_cert
  class_attribute :crypt_key
  class_attribute :crypt_passphrase

  def certs_path=(path)
    @certs_path = File.new(path)
  end

  def sign_cert
    certs_path.join(super)
  end

  def sign_key
    certs_path.join(super)
  end

  def crypt_cert
    certs_path.join(super)
  end

  def crypt_key
    certs_path.join(super)
  end

  def get_crypter
    ActionMailerX509::X509.new(
        crypt_cert,
        crypt_key,
        crypt_passphrase,
        crypt_cipher)
  end

  def get_signer
    ActionMailerX509::X509.new(
        sign_cert,
        sign_key,
        sign_passphrase)
  end
end