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
require 'actionmailer_x509/x509'
require 'actionmailer_x509/configuration'
require 'openssl'
require 'overrides/action_mailer/base'
require 'overrides/mail/message'

module ActionMailerX509
  mattr_reader :configurations

  mattr_accessor :default_configuration

  class << self
    def settings
      yield self
    end

    def configurations
      @configurations ||= {}
    end

    def add_configuration(name, params = {})
      configurations[name.to_sym] = Configuration.new(params)
    end

    def get_configuration(name)
      configurations[(name || ActionMailerX509.default_configuration).to_sym]
    end
  end
end
