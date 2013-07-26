require 'openssl'

module ActionMailerX509
  class X509
    attr_accessor :certificate, :cipher, :rsa_key, :certificate_store

    def initialize(certificate_file, rsa_key_file, pass_phrase = '', cipher_type_str = 'des')
      @certificate = OpenSSL::X509::Certificate.new(File::read(certificate_file))
      @rsa_key = OpenSSL::PKey::RSA.new(File::read(rsa_key_file), pass_phrase)
      @cipher = OpenSSL::Cipher.new(cipher_type_str)

      @certificate_store = OpenSSL::X509::Store.new
      @certificate_store.add_cert(certificate)
    end

    def encode(text)
      write OpenSSL::PKCS7.encrypt([certificate], text, cipher)
      #OpenSSL::PKCS7.encrypt([certificate], text, cipher, OpenSSL::PKCS7::BINARY)
    end

    def decode(encrypted_text)
      pkcs7 = read(encrypted_text) rescue OpenSSL::PKCS7.new(encrypted_text)
      pkcs7.decrypt(@rsa_key, certificate)
    rescue encrypted_text
    end

    def sign(text)
      write OpenSSL::PKCS7.sign(certificate, rsa_key, text, [], OpenSSL::PKCS7::DETACHED)
      #OpenSSL::PKCS7.sign(certificate, rsa_key, text, [], OpenSSL::PKCS7::BINARY)
    end

    def verify(text)
      result = read(text).verify(nil, @certificate_store, nil, nil)
      #read(text).verify(nil, @certificate_store, nil, OpenSSL::PKCS7::NOVERIFY)
      result ? read(text).data : nil
    end

    protected
      def write(pcks7)
        OpenSSL::PKCS7::write_smime pcks7
      end

      def read(text)
        OpenSSL::PKCS7.read_smime text
      end
  end
end


#PAYPAL_CERT_PEM = File.read("paypal_cert.pem")
#@paypal_cert = OpenSSL::X509::Certificate.new(PAYPAL_CERT_PEM)
#
#APP_CERT_PEM = File.read("app_cert.pem")
#@app_cert = OpenSSL::X509::Certificate.new(APP_CERT_PEM)
#
#APP_KEY_PEM = File.read("app_key.pem")
#@app_key = OpenSSL::PKey::RSA.new(APP_KEY_PEM, '')
#
#PAYPAL_KEY_PEM = File.read("paypal_key.pem")
#@paypal_key = OpenSSL::PKey::RSA.new(PAYPAL_KEY_PEM, '')
#
#CERT_STORE = OpenSSL::X509::Store.new
#CERT_STORE.add_cert(@app_cert)
#
#data = Hash.new
#data['customer_id'] = '123456789'
#data['customer_name'] = 'Mr Smith'
#
#def encrypt_for_paypal(values)
#  data_name_values = values.map { |k, v| "#{k}=#{v}" }
#
#  signed_data = OpenSSL::PKCS7::sign(@app_cert, @app_key, data_name_values.join("\n"), [], OpenSSL::PKCS7::BINARY)
#
#  cypher = OpenSSL::Cipher::new("AES-128-CFB")
#
#  encrypted_data = OpenSSL::PKCS7::encrypt([@paypal_cert], signed_data.to_der, cypher, OpenSSL::PKCS7::BINARY)
#
#  encrypted_data.to_s #.gsub("\n", "")
#end
#
#def decrypt_by_paypal(encrypted_data)
#  received_encrypted_data = OpenSSL::PKCS7.new(encrypted_data)
#
#  received_signed_data = received_encrypted_data.decrypt(@paypal_key, @paypal_cert)
#
#  p7_received_signed_data = OpenSSL::PKCS7.new(received_signed_data)
#
#  p7_received_signed_data.verify(nil, CERT_STORE, nil, OpenSSL::PKCS7::NOVERIFY)
#
#  p7_received_signed_data.data
#end