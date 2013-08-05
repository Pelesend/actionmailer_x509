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

  class_attribute :sign_cert
  class_attribute :sign_key
  class_attribute :sign_passphrase
  class_attribute :crypt_cert
  class_attribute :crypt_key
  class_attribute :crypt_passphrase

  def sign_require?
    sign_enable == true
  end

  def crypt_require?
    crypt_enable == true
  end

  def certs_path=(path)
    @certs_path = Pathname.new(path)
  end

  def sign_cert
    certs_path.join(@sign_cert)
  end

  def sign_key
    certs_path.join(@sign_key)
  end

  def crypt_cert
    certs_path.join(@crypt_cert)
  end

  def crypt_key
    certs_path.join(@crypt_key)
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