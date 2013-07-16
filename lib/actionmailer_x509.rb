# Copyright (c) 2007 Fabien Penso <fabien.penso@conovae.com>
#
# actionmailer_x509 is a rails plugin to allow X509 outgoing mail to be X509
# signed.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the University of California, Berkeley nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
require 'actionmailer_x509/railtie' if defined?(Rails)
require "openssl"

module ActionMailer #:nodoc:
  class Base #:nodoc:
    class_attribute :x509
    self.x509 = {
      sign_cert: "certs/server.crt",
      sign_key: "certs/server.key",        
      sign_passphrase: "hisp",
      crypt_cert: "certs/ca.crt",
      crypt_cipher: 'des'
    }

    # unfortinately, we should run really deep here
    # and overwrite initializer
    # to get @_message object
    def initialize(method_name=nil, *args)
      super()
      @_mail_was_called = false
      @_message = x509_smime(Mail.new)
      process(method_name, *args) if method_name
    end

  private
    # X509 SMIME signing and\or crypting
    def x509_smime(message)
      # We should set content_id, otherwise Mail will set content_id after signing and will broke sign
      message.content_id ||= nil
      message.parts.each { |p| p.content_id ||= nil }

      # Load certificate and private key
      sign_cert = OpenSSL::X509::Certificate.new( File::read(self.x509[:sign_cert]) )
      sign_prv_key = OpenSSL::PKey::RSA.new( File::read(self.x509[:sign_key]), self.x509[:sign_passphrase])
      crypt_cert = OpenSSL::X509::Certificate.new( File::read(self.x509[:crypt_cert]) )
      cipher = OpenSSL::Cipher.new(self.x509[:crypt_cipher])
      

      # NOTE: the one following line is the slowest part of this code, signing is sloooow
      p7 = message.encoded
      p7 = OpenSSL::PKCS7.sign(sign_cert,sign_prv_key, p7, [], OpenSSL::PKCS7::DETACHED)
      p7 = OpenSSL::PKCS7.encrypt([crypt_cert], OpenSSL::PKCS7::write_smime(p7), cipher, nil)
      smime0 = OpenSSL::PKCS7::write_smime(p7)

      # Adding the signature part to the older mail
      newm = Mail.new(smime0)

      # We need to overwrite the content-type of the mail so MUA notices this is a signed mail
      # newm.content_type = 'multipart/signed; protocol="application/x-pkcs7-signature"; micalg=sha1; '
      newm.delivery_method(message.delivery_method.class, message.delivery_method.settings)
      newm.subject = message.subject
      newm.to = message.to
      newm.cc = message.cc
      newm.from = message.from
      newm.mime_version = message.mime_version
      newm.date = message.date
      newm.body = "This is an S/MIME signed message\n"

      newm
    end
  end
end
