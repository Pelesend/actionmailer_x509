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
      pkcs7 = read(encrypted_text)
      pkcs7.decrypt(@rsa_key, certificate)
    rescue
      nil
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
      def set_format(text)
        text.gsub("\r\n", ActionMailerX509.newline_sequence)
      end

      def write(pcks7)
        OpenSSL::PKCS7::write_smime pcks7
      end

      def read(text)
        OpenSSL::PKCS7.read_smime(text) rescue OpenSSL::PKCS7.new(text)
      end
  end
end
