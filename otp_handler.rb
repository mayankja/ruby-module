module OtpHandler
  def self.included(klass)
    klass.extend ClassMethods
    klass.send(:include, InstanceMethods)
  end

  module ClassMethods
    def required_fields
      [:otp_confirmed_at, :otp_sent_at, :otp_token, :otp_type]
    end

    def with_otp_token(token, otp_type)
      otp_authenticate_token = otp_digest(:otp_token, token, otp_type)
      where(otp_token: otp_authenticate_token, otp_type: otp_type).first
    end

    def send_otp_instructions(phone_or_email_field, value, otp_type)
      otp_obj = where({phone_field => value}).first
      otp_obj.send_otp_instructions(otp_type) unless otp_obj.blank?
      otp_obj
    end

    def confirm_otp_by_token(original_token, otp_type, params)      
      otp_obj = with_otp_token(original_token, otp_type)
      unless otp_obj.blank?
        if otp_obj.otp_period_valid?
          otp_obj.set_otp_confirmed_at(Time.now.utc)
          otp_obj.after_otp_confirmed(params, otp_type)
        else
          otp_obj.errors.add(:otp_token, :expired)
        end
      end
      otp_obj
    end

    def otp_key_for(column, otp_type)
      "OtpHandler #{column} #{otp_type}"
    end

    def otp_digest(column, value, otp_type)
      key = otp_key_for(column, otp_type)
      value.present? && OpenSSL::HMAC.hexdigest("SHA256", key, value)
    end

    def otp_generate(column, otp_type)
      loop do
        raw = SecureRandom.uuid.gsub(/[^a-z0-9]/,"").slice(1..6)
        raw = "123456" if Rails.env.test?
        enc = otp_digest(column, raw, otp_type)
        break [raw, enc] unless where({column => enc}).first
      end
    end
  end

  module InstanceMethods
    def otp_within
      1.hours
    end

    def set_otp_confirmed_at(confirmed_at)
      clear_otp_token     
      self.otp_confirmed_at = confirmed_at
      save(validate: false)
    end

    def otp_period_valid?
      otp_sent_at && otp_sent_at.utc >= self.otp_within.ago.utc
    end

    def compose_otp_instructions_message(token)
      message = "One Time Password for biomark is #{token}. Please use the password to complete the request. Plz do not share this with anyone."
      message
    end

    def send_otp_instructions(otp_type)
      token = set_otp_token(otp_type)
      message = compose_otp_instructions_message(token)
      send_otp_instructions_message(token, message)
      token
    end

    def send_otp_instructions_message(token, message)
      puts message
    end

    def after_otp_confirmed(params)
      puts message params
    end

    private

    def clear_otp_token
      self.otp_token = nil
      self.otp_sent_at = nil
      self.otp_type = nil
    end

    def set_otp_token(otp_type)
      raw, enc = self.class.otp_generate(:otp_token, otp_type)
      self.otp_token = enc
      self.otp_sent_at = Time.now.utc
      self.otp_type = otp_type
      save(validate: false)
      raw
    end
  end
end
